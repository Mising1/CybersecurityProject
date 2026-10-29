use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

use crate::{
    auth::{self, CurrentUser, SESSION_COOKIE},
    db::{self, PASSWORD_HISTORY_LEN},
    error::AppError,
    rbac::{Permission, Role},
    security, AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/password", post(change_password))
        .route("/auth/password-policy", get(password_policy))
}

#[derive(Deserialize)]
struct LoginRequest { username: String, password: String }

#[derive(Deserialize)]
struct Credentials {
    id: RecordId,
    password_hash: String,
    password_history: Vec<String>,
    blocked: bool,
    must_change_password: bool,
    otp_expired: bool,
    password_expired: bool,
}

fn credentials_query(source: &str) -> String {
    format!(
        "SELECT id, password_hash, password_history, blocked, must_change_password, otp_expired, password_expired \
         FROM ONLY {source} LIMIT 1"
    )
}

#[derive(Serialize)]
struct LoginResponse { must_change_password: bool }

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), AppError> {
    let user: Option<Credentials> = state.db
        .query(credentials_query("user WHERE username = $username"))
        .bind(("username", req.username))
        .await?
        .take(0)?;

    // hasło jest weryfikowane zawsze, także dla nieistniejącego loginu (patrz DUMMY_HASH)
    let hash = user.as_ref().map_or_else(|| security::DUMMY_HASH.clone(), |u| u.password_hash.clone());
    let valid = tokio::task::spawn_blocking(move || security::verify_password(&req.password, &hash)).await?;
    let user = match user {
        Some(u) if valid && !u.blocked => u,
        _ => return Err(AppError::InvalidCredentials),
    };
    // to już nic nie zdradza - hasło było poprawne
    if user.otp_expired {
        return Err(AppError::OneTimePasswordExpired);
    }

    // poprzednia sesja z tej przeglądarki przestaje obowiązywać, a nowa dostaje nowy token (ochrona przed session fixation)
    if let Some(old) = jar.get(SESSION_COOKIE) {
        auth::delete_session(&state.db, old.value()).await?;
    }
    let token = security::new_session_token();
    state.db
        .query("CREATE session SET user = $user, token_hash = $hash")
        .bind(("user", user.id))
        .bind(("hash", security::hash_token(&token)))
        .await?
        .check()?;

    let response = LoginResponse { must_change_password: user.must_change_password || user.password_expired };
    Ok((jar.add(auth::session_cookie(token, state.cfg.cookie_secure)), Json(response)))
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> Result<(CookieJar, StatusCode), AppError> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        auth::delete_session(&state.db, cookie.value()).await?;
    }
    Ok((jar.remove(auth::removal_cookie()), StatusCode::NO_CONTENT))
}

#[derive(Serialize)]
struct Me {
    username: String,
    role: Role,
    permissions: Vec<Permission>,
    must_change_password: bool,
    /// frontend wylogowuje po tym czasie bez zapytań do API - tak samo liczy go serwer
    idle_timeout_minutes: u32,
}

async fn me(State(state): State<AppState>, user: CurrentUser) -> Result<Json<Me>, AppError> {
    Ok(Json(Me {
        permissions: user.role.permissions(),
        username: user.username,
        role: user.role,
        must_change_password: user.must_change_password,
        idle_timeout_minutes: db::settings(&state.db).await?.idle_timeout_minutes,
    }))
}

#[derive(Deserialize)]
struct ChangePassword { current_password: String, new_password: String }

async fn change_password(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(req): Json<ChangePassword>,
) -> Result<StatusCode, AppError> {
    let creds: Option<Credentials> = state.db
        .query(credentials_query("$id"))
        .bind(("id", user.id.clone()))
        .await?
        .take(0)?;
    let creds = creds.ok_or(AppError::Unauthorized)?;

    let current = req.current_password.clone();
    let current_hash = creds.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || security::verify_password(&current, &current_hash)).await?;
    // 400, a nie 401 - błędne obecne hasło nie kończy sesji
    if !valid {
        return Err(AppError::BadRequest("Obecne hasło jest niepoprawne."));
    }
    if creds.otp_expired {
        return Err(AppError::OneTimePasswordExpired);
    }
    db::password_policy(&state.db).await?.check(&req.new_password).map_err(AppError::BadRequest)?;

    // obecne hasło (także jednorazowe) i ostatnie hasła ustawione przez użytkownika
    let mut previous = creds.password_history;
    if !previous.contains(&creds.password_hash) {
        previous.push(creds.password_hash);
    }
    let new_password = req.new_password.clone();
    let reused = tokio::task::spawn_blocking(move || {
        previous.iter().any(|hash| security::verify_password(&new_password, hash))
    }).await?;
    if reused {
        return Err(AppError::BadRequest("Nowe hasło musi się różnić od 3 ostatnio używanych haseł."));
    }

    let hash = tokio::task::spawn_blocking(move || security::hash_password(&req.new_password)).await??;
    state.db
        .query(
            "UPDATE $id SET password_hash = $hash, must_change_password = false, one_time_expires_at = NONE, \
             password_changed_at = time::now(), \
             password_history = array::slice(array::prepend(password_history, $hash), 0, $history_len)",
        )
        .query("DELETE session WHERE user = $id AND id != $current_session")  // pozostałe sesje tracą ważność
        .bind(("id", user.id))
        .bind(("hash", hash))
        .bind(("current_session", user.session_id))
        .bind(("history_len", PASSWORD_HISTORY_LEN))
        .await?
        .check()?;
    Ok(StatusCode::NO_CONTENT)
}

async fn password_policy(State(state): State<AppState>, _user: CurrentUser) -> Result<Json<security::PasswordPolicy>, AppError> {
    Ok(Json(db::password_policy(&state.db).await?))
}
