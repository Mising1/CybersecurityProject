use std::time::Duration;

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use surrealdb::RecordId;

use crate::{db::Db, error::AppError, rbac::{Permission, Role}, security, AppState};

pub const SESSION_COOKIE: &str = "session";

const IDLE_LIMIT: &str = "time::now() - duration::from::mins(settings:main.idle_timeout_minutes)";

/// Zalogowany użytkownik. Użycie jako argumentu handlera wymusza ważną sesję
/// i przedłuża ją (last_seen), a sesja nieaktywna dłużej niż idle_timeout_minutes jest usuwana.
pub struct CurrentUser {
    pub id: RecordId,
    pub session_id: RecordId,
    pub username: String,
    pub role: Role,
    /// hasło jednorazowe albo wygasłe (starsze niż password_valid_days)
    pub must_change_password: bool,
}

impl CurrentUser {
    /// Dopóki hasło jednorazowe nie zostanie zmienione, żadne uprawnienie nie działa.
    pub fn require(&self, permission: Permission) -> Result<(), AppError> {
        if self.must_change_password {
            return Err(AppError::PasswordChangeRequired);
        }
        if self.role.has(permission) { Ok(()) } else { Err(AppError::Forbidden) }
    }
}

#[derive(Deserialize)]
struct SessionRow {
    id: RecordId,
    user: RecordId,
    username: String,
    role: Role,
    blocked: bool,
    must_change_password: bool,
    expired: bool,
}

#[async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar.get(SESSION_COOKIE).ok_or(AppError::Unauthorized)?;

        let session: Option<SessionRow> = state.db
            .query(format!(
                "SELECT id, user, user.username AS username, user.role AS role, user.blocked AS blocked, \
                 (user.must_change_password OR user.password_expired) AS must_change_password, last_seen < {IDLE_LIMIT} AS expired \
                 FROM ONLY session WHERE token_hash = $hash LIMIT 1"
            ))
            .bind(("hash", security::hash_token(token.value())))
            .await?
            .take(0)?;
        let session = session.ok_or(AppError::Unauthorized)?;

        if session.expired || session.blocked {
            state.db.query("DELETE $id").bind(("id", session.id)).await?.check()?;
            return Err(AppError::Unauthorized);
        }
        state.db.query("UPDATE $id SET last_seen = time::now()").bind(("id", session.id.clone())).await?.check()?;

        Ok(Self {
            id: session.user,
            session_id: session.id,
            username: session.username,
            role: session.role,
            must_change_password: session.must_change_password,
        })
    }
}

pub fn session_cookie(token: String, secure: bool) -> Cookie<'static> {
    // bez Max-Age: ciasteczko znika po zamknięciu przeglądarki, a o wygaśnięciu i tak decyduje serwer
    Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .build()
}

pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE).path("/").build()
}

pub async fn delete_session(db: &Db, token: &str) -> surrealdb::Result<()> {
    db.query("DELETE session WHERE token_hash = $hash")
        .bind(("hash", security::hash_token(token)))
        .await?
        .check()?;
    Ok(())
}

/// Co minutę usuwa sesje, które wygasły z powodu bezczynności.
pub async fn purge_expired_sessions(db: Db) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let result = db.query(format!("DELETE session WHERE last_seen < {IDLE_LIMIT}")).await.and_then(|r| r.check());
        if let Err(e) = result {
            eprintln!("czyszczenie sesji: {e}");
        }
    }
}
