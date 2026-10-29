use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    InvalidCredentials,
    OneTimePasswordExpired,
    Unauthorized,
    Forbidden,
    PasswordChangeRequired,
    NotFound,
    BadRequest(&'static str),
    Conflict(&'static str),
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Login lub hasło niepoprawne"),
            Self::OneTimePasswordExpired =>
                (StatusCode::UNAUTHORIZED, "Hasło jednorazowe wygasło. Poproś administratora o nowe."),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Sesja wygasła lub nie jesteś zalogowany."),
            Self::Forbidden => (StatusCode::FORBIDDEN, "Brak uprawnień."),
            Self::PasswordChangeRequired => (StatusCode::FORBIDDEN, "Najpierw ustaw nowe hasło."),
            Self::NotFound => (StatusCode::NOT_FOUND, "Nie znaleziono."),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Self::Conflict(m) => (StatusCode::CONFLICT, m),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Błąd serwera."),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<surrealdb::Error> for AppError {
    fn from(e: surrealdb::Error) -> Self {
        eprintln!("błąd bazy: {e}");
        Self::Internal
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(e: argon2::password_hash::Error) -> Self {
        eprintln!("błąd hashowania: {e}");
        Self::Internal
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(e: tokio::task::JoinError) -> Self {
        eprintln!("błąd zadania: {e}");
        Self::Internal
    }
}
