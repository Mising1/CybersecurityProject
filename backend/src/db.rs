use serde::{Deserialize, Serialize};
use surrealdb::{engine::remote::http::{Client, Http}, opt::auth::Root, RecordId, Surreal};

use crate::{config::Config, error::AppError, rbac::Role, security::{self, PasswordPolicy}};

pub type Db = Surreal<Client>;

pub const ADMIN_USERNAME: &str = "ADMIN";

pub const PASSWORD_HISTORY_LEN: usize = 3;

const ONE_TIME_EXPIRY: &str = "time::now() + duration::from::hours(settings:main.one_time_valid_hours)";

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub min_length: usize,
    pub passphrase_rule_enabled: bool,
    pub password_valid_days: u32,
    pub idle_timeout_minutes: u32,
    pub one_time_valid_hours: u32,
}

pub async fn connect(cfg: &Config) -> Result<Db, Box<dyn std::error::Error>> {
    let db = Surreal::new::<Http>(cfg.db_url.as_str()).await?;
    db.signin(Root { username: &cfg.db_user, password: &cfg.db_pass }).await?;
    db.use_ns("app").use_db("app").await?;

    db.query(include_str!("schema.surql")).await?.check()?;

    db.query("INSERT IGNORE INTO settings { id: settings:main }").await?.check()?;
    Ok(db)
}

pub async fn create_user(db: &Db, username: &str, role: Role, password_hash: String) -> surrealdb::Result<String> {
    let expires_at: Option<String> = db
        .query(format!(
            "CREATE ONLY user SET username = $username, role = $role, password_hash = $hash, \
             must_change_password = true, one_time_expires_at = {ONE_TIME_EXPIRY}, password_changed_at = NONE \
             RETURN VALUE <string> one_time_expires_at"
        ))
        .bind(("username", username.to_string()))
        .bind(("role", role))
        .bind(("hash", password_hash))
        .await?
        .take(0)?;
    Ok(expires_at.unwrap_or_default())
}

pub async fn reset_password(db: &Db, username: &str, password_hash: String) -> surrealdb::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Updated { id: RecordId, expires_at: String }

    let updated: Vec<Updated> = db
        .query(format!(
            "UPDATE user SET password_hash = $hash, must_change_password = true, one_time_expires_at = {ONE_TIME_EXPIRY}, \
             password_changed_at = NONE WHERE username = $username RETURN id, <string> one_time_expires_at AS expires_at"
        ))
        .bind(("username", username.to_string()))
        .bind(("hash", password_hash))
        .await?
        .take(0)?;
    let Some(user) = updated.into_iter().next() else { return Ok(None) };

    db.query("DELETE session WHERE user = $id").bind(("id", user.id)).await?.check()?;
    Ok(Some(user.expires_at))
}

pub async fn password_policy(db: &Db) -> Result<PasswordPolicy, AppError> {
    let policy: Option<PasswordPolicy> = db
        .query("SELECT min_length, passphrase_rule_enabled FROM ONLY settings:main")
        .await?
        .take(0)?;
    policy.ok_or(AppError::Internal)
}

pub async fn settings(db: &Db) -> Result<Settings, AppError> {
    let settings: Option<Settings> = db.query("SELECT * OMIT id FROM ONLY settings:main").await?.take(0)?;
    settings.ok_or(AppError::Internal)
}

// jeśli hasło jednorazowe admina wygasło przed pierwszym logowaniem, dostaje nowe
pub async fn ensure_admin(db: &Db) -> Result<(), Box<dyn std::error::Error>> {
    let otp_expired: Option<bool> = db
        .query("SELECT VALUE otp_expired FROM ONLY user WHERE username = $username LIMIT 1")
        .bind(("username", ADMIN_USERNAME))
        .await?
        .take(0)?;
    if otp_expired == Some(false) {
        return Ok(());
    }

    let password = security::one_time_password();
    let hash = security::hash_password(&password).map_err(|e| e.to_string())?;
    let expires_at = match otp_expired {
        None => create_user(db, ADMIN_USERNAME, Role::Administrator, hash).await?,
        Some(_) => reset_password(db, ADMIN_USERNAME, hash).await?.unwrap_or_default(),
    };
    println!("Konto {ADMIN_USERNAME} - hasło jednorazowe: {password} (ważne do {expires_at})");
    Ok(())
}

pub async fn seed(db: &Db) -> surrealdb::Result<()> {
    db.query(include_str!("seed.surql")).await?.check()?;
    Ok(())
}
