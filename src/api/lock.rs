use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use super::types::{make_error, ApiError, AppState, GenericRes};

/// Removes an unlocked vault from memory.
pub(crate) async fn lock(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<GenericRes>, ApiError> {
    let mut vaults = state.unlocked_vaults.write().await;

    if vaults.remove(&name).is_some() {
        Ok(Json(GenericRes {
            message: format!("Vault {} locked", name),
        }))
    } else {
        Err(make_error(StatusCode::NOT_FOUND, "Vault not unlocked"))
    }
}