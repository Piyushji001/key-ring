//! Search commands. The index lives in `AppState` and is rebuilt on unlock and
//! after every mutation, so these never touch SQLite.

use keyring_vault::RecordType;
use tauri::State;

use crate::error::Result;
use crate::model::dto::SearchHitDto;
use crate::state::AppState;

/// The main window shows a long list; the Phase 5 overlay will ask for 8.
const DEFAULT_LIMIT: usize = 200;

#[tauri::command]
pub fn search(
    state: State<'_, AppState>,
    query: String,
    limit: Option<u32>,
) -> Result<Vec<SearchHitDto>> {
    let limit = limit.map(|l| l as usize).unwrap_or(DEFAULT_LIMIT).min(1000);
    let now = keyring_vault::util::time::now_unix();

    let hits = state.with_index(|index| Ok(index.search(&query, limit, now)))?;

    Ok(hits
        .into_iter()
        .map(|h| SearchHitDto {
            type_label: h.record_type.label().to_string(),
            record_type: h.record_type.as_str().to_string(),
            record_id: h.record_id,
            title: h.title,
            folder: h.folder,
            favorite: h.favorite,
            matched_field: h.matched_field,
            matched_context: h.matched_context,
        })
        .collect())
}

/// How many records the index holds. Used by the Phase 4 acceptance test that
/// checks search latency against 10,000 records.
#[tauri::command]
pub fn index_size(state: State<'_, AppState>) -> Result<usize> {
    state.with_index(|index| Ok(index.len()))
}

/// Force a rebuild. The UI should not normally need this - every mutating
/// command rebuilds already - but importing or restoring can change everything
/// at once.
#[tauri::command]
pub fn rebuild_index(state: State<'_, AppState>) -> Result<usize> {
    state.rebuild_index();
    state.with_index(|index| Ok(index.len()))
}

/// Expose the type keys so the frontend can build filter chips without
/// hardcoding the list.
#[tauri::command]
pub fn type_keys() -> Vec<String> {
    RecordType::ALL
        .into_iter()
        .map(|t| t.as_str().to_string())
        .collect()
}
