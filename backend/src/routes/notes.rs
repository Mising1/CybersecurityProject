use axum::{extract::{Path, State}, http::StatusCode, routing::{get, post, put}, Json, Router};
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

use crate::{auth::CurrentUser, error::AppError, rbac::Permission, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/notes", get(list).post(add))
        .route("/notes/:id", put(edit))
        .route("/notes/:id/approve", post(approve))
}

#[derive(Serialize, Deserialize)]
struct Note { id: String, text: String, author: Option<String>, approved: bool, approved_by: Option<String> }

async fn list(State(state): State<AppState>, user: CurrentUser) -> Result<Json<Vec<Note>>, AppError> {
    user.require(Permission::ReadContent)?;
    let sees_drafts = user.role.has(Permission::EditContent) || user.role.has(Permission::ApproveContent);
    let notes: Vec<Note> = state.db
        .query(
            "SELECT record::id(id) AS id, text, author, approved, approved_by, created_at FROM note \
             WHERE approved OR $drafts ORDER BY created_at",
        )
        .bind(("drafts", sees_drafts))
        .await?
        .take(0)?;
    Ok(Json(notes))
}

#[derive(Deserialize)]
struct NoteText { text: String }

fn validate(note: &NoteText) -> Result<(), AppError> {
    if note.text.trim().is_empty() {
        return Err(AppError::BadRequest("Notatka nie może być pusta."));
    }
    Ok(())
}

async fn add(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(note): Json<NoteText>,
) -> Result<StatusCode, AppError> {
    user.require(Permission::EditContent)?;
    validate(&note)?;
    state.db
        .query("CREATE note SET text = $text, author = $author")
        .bind(("text", note.text))
        .bind(("author", user.username))
        .await?
        .check()?;
    Ok(StatusCode::CREATED)
}

async fn edit(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(note): Json<NoteText>,
) -> Result<StatusCode, AppError> {
    user.require(Permission::EditContent)?;
    validate(&note)?;
    let updated: Vec<RecordId> = state.db
        .query("UPDATE $id SET text = $text, approved = false, approved_by = NONE RETURN VALUE id")
        .bind(("id", RecordId::from(("note", id))))
        .bind(("text", note.text))
        .await?
        .take(0)?;
    if updated.is_empty() {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn approve(State(state): State<AppState>, user: CurrentUser, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    user.require(Permission::ApproveContent)?;
    let updated: Vec<RecordId> = state.db
        .query("UPDATE $id SET approved = true, approved_by = $by RETURN VALUE id")
        .bind(("id", RecordId::from(("note", id))))
        .bind(("by", user.username))
        .await?
        .take(0)?;
    if updated.is_empty() {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
