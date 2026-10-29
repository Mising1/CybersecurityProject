use std::env;

pub struct Config {
    pub db_url: String,
    pub db_user: String,
    pub db_pass: String,
    pub bind_addr: String,
    /// true na produkcji (HTTPS) - ciasteczko sesji dostaje flagę Secure
    pub cookie_secure: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let var = |key: &str, default: &str| env::var(key).unwrap_or_else(|_| default.to_string());
        Self {
            db_url: var("DB_URL", "127.0.0.1:8000"),
            db_user: var("DB_USER", "root"),
            db_pass: var("DB_PASS", "root"),
            bind_addr: var("BIND_ADDR", "0.0.0.0:3000"),
            cookie_secure: var("COOKIE_SECURE", "false") == "true",
        }
    }
}
