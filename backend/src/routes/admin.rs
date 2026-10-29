use axum::{extract::{Path, State}, http::StatusCode, routing::{get, post, put}, Json, Router};
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

use crate::{
    auth::CurrentUser,
    db::{self, Settings, ADMIN_USERNAME},
    error::AppError,
    rbac::{Permission, Role},
    security,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users).post(create_user))
        .route("/admin/users/:username", put(update_user).delete(delete_user))
        .route("/admin/users/:username/blocked", put(set_blocked))
        .route("/admin/users/:username/password", post(reset_password))
        .route("/admin/settings", get(get_settings).put(update_settings))
}

#[derive(Serialize, Deserialize)]
struct UserInfo { username: String, role: Role, blocked: bool, must_change_password: bool, password_expired: bool }

async fn list_users(State(state): State<AppState>, user: CurrentUser) -> Result<Json<Vec<UserInfo>>, AppError> {
    user.require(Permission::ManageUsers)?;
    let users: Vec<UserInfo> = state.db
        .query("SELECT username, role, blocked, must_change_password, password_expired FROM user ORDER BY username")
        .await?
        .take(0)?;
    Ok(Json(users))
}

#[derive(Deserialize)]
struct NewUser { username: String, role: Role }

#[derive(Serialize)]
struct OneTimePassword { username: String, one_time_password: String, expires_at: String }

async fn generate_one_time_password() -> Result<(String, String), AppError> {
    let password = security::one_time_password();
    let to_hash = password.clone();
    let hash = tokio::task::spawn_blocking(move || security::hash_password(&to_hash)).await??;
    Ok((password, hash))
}

async fn create_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(req): Json<NewUser>,
) -> Result<(StatusCode, Json<OneTimePassword>), AppError> {
    user.require(Permission::ManageUsers)?;
    let username = req.username.trim().to_string();
    if username.is_empty() {
        return Err(AppError::BadRequest("Login nie może być pusty."));
    }

    let existing: Option<RecordId> = state.db
        .query("SELECT VALUE id FROM ONLY user WHERE username = $username LIMIT 1")
        .bind(("username", username.clone()))
        .await?
        .take(0)?;
    if existing.is_some() {
        return Err(AppError::Conflict("Taki login już istnieje."));
    }

    let (password, hash) = generate_one_time_password().await?;
    let expires_at = db::create_user(&state.db, &username, req.role, hash).await?;

    Ok((StatusCode::CREATED, Json(OneTimePassword { username, one_time_password: password, expires_at })))
}

#[derive(Deserialize)]
struct Blocked { blocked: bool }

async fn set_blocked(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(username): Path<String>,
    Json(req): Json<Blocked>,
) -> Result<StatusCode, AppError> {
    user.require(Permission::ManageUsers)?;
    protect(&user, &username, "Nie można zablokować własnego konta.", "Wbudowanego konta ADMIN nie można zablokować.")?;

    let ids: Vec<RecordId> = state.db
        .query("UPDATE user SET blocked = $blocked WHERE username = $username RETURN VALUE id")
        .bind(("blocked", req.blocked))
        .bind(("username", username))
        .await?
        .take(0)?;
    if ids.is_empty() {
        return Err(AppError::NotFound);
    }
    if req.blocked {
        state.db.query("DELETE session WHERE user IN $ids").bind(("ids", ids)).await?.check()?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn reset_password(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(username): Path<String>,
) -> Result<Json<OneTimePassword>, AppError> {
    user.require(Permission::ManageUsers)?;
    if username == user.username {
        return Err(AppError::BadRequest("Własne hasło zmień w ustawieniach konta."));
    }

    let (password, hash) = generate_one_time_password().await?;
    let expires_at = db::reset_password(&state.db, &username, hash).await?.ok_or(AppError::NotFound)?;
    Ok(Json(OneTimePassword { username, one_time_password: password, expires_at }))
}

async fn get_settings(State(state): State<AppState>, user: CurrentUser) -> Result<Json<Settings>, AppError> {
    user.require(Permission::ManageSettings)?;
    Ok(Json(db::settings(&state.db).await?))
}

#[derive(Deserialize)]
struct SettingsUpdate { passphrase_rule_enabled: bool, password_valid_days: u32, idle_timeout_minutes: u32 }

async fn update_settings(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(req): Json<SettingsUpdate>,
) -> Result<Json<Settings>, AppError> {
    user.require(Permission::ManageSettings)?;
    if !(1..=3650).contains(&req.password_valid_days) {
        return Err(AppError::BadRequest("Ważność hasła musi wynosić od 1 do 3650 dni."));
    }
    if !(1..=1440).contains(&req.idle_timeout_minutes) {
        return Err(AppError::BadRequest("Limit bezczynności musi wynosić od 1 do 1440 minut."));
    }
    state.db
        .query(
            "UPDATE settings:main SET passphrase_rule_enabled = $passphrase, \
             password_valid_days = $valid_days, idle_timeout_minutes = $idle_minutes",
        )
        .bind(("passphrase", req.passphrase_rule_enabled))
        .bind(("valid_days", req.password_valid_days))
        .bind(("idle_minutes", req.idle_timeout_minutes))
        .await?
        .check()?;
    Ok(Json(db::settings(&state.db).await?))
}

// nie można zablokować, usunąć ani zmienić roli sobie ani kontu ADMIN - system nie może zostać bez admina
fn protect(user: &CurrentUser, username: &str, own: &'static str, builtin: &'static str) -> Result<(), AppError> {
    if username == user.username {
        return Err(AppError::BadRequest(own));
    }
    if username == ADMIN_USERNAME {
        return Err(AppError::BadRequest(builtin));
    }
    Ok(())
}

#[derive(Deserialize)]
struct UserUpdate { role: Role }

async fn update_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(username): Path<String>,
    Json(req): Json<UserUpdate>,
) -> Result<StatusCode, AppError> {
    user.require(Permission::ManageUsers)?;
    protect(&user, &username, "Nie można zmienić roli własnego konta.", "Roli konta ADMIN nie można zmienić.")?;

    let ids: Vec<RecordId> = state.db
        .query("UPDATE user SET role = $role WHERE username = $username RETURN VALUE id")
        .bind(("role", req.role))
        .bind(("username", username))
        .await?
        .take(0)?;
    if ids.is_empty() {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(username): Path<String>,
) -> Result<StatusCode, AppError> {
    user.require(Permission::ManageUsers)?;
    protect(&user, &username, "Nie można usunąć własnego konta.", "Konta ADMIN nie można usunąć.")?;

    let ids: Vec<RecordId> = state.db
        .query("DELETE user WHERE username = $username RETURN BEFORE")
        .bind(("username", username))
        .await?
        .take((0, "id"))?;
    if ids.is_empty() {
        return Err(AppError::NotFound);
    }
    state.db.query("DELETE session WHERE user IN $ids").bind(("ids", ids)).await?.check()?;
    Ok(StatusCode::NO_CONTENT)
}
