mod auth;
mod config;
mod db;
mod error;
mod rbac;
mod security;

mod routes {
    pub mod admin;
    pub mod auth;
    pub mod notes;
}

use std::sync::Arc;

use axum::Router;

use config::Config;
use db::Db;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Arc<Config>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Arc::new(Config::from_env());
    let db = db::connect(&cfg).await?;
    db::ensure_admin(&db).await?;
    if std::env::args().nth(1).as_deref() == Some("seed") {
        db::seed(&db).await?;
        println!("Utworzono konta testowe (src/seed.surql)");
        return Ok(());
    }
    // liczymy od razu, żeby pierwsze logowanie nie trwało dłużej niż kolejne
    std::sync::LazyLock::force(&security::DUMMY_HASH);
    tokio::spawn(auth::purge_expired_sessions(db.clone()));

    let app = Router::new()
        .merge(routes::auth::router())
        .merge(routes::admin::router())
        .merge(routes::notes::router())
        .with_state(AppState { db, cfg: cfg.clone() });

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    println!("API nasłuchuje na {}", cfg.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
