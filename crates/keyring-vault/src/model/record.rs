use super::record_type::RecordType;

/// A record as stored in the `records` table.
#[derive(Debug, Clone)]
pub struct RecordRow {
    pub id: String,
    pub record_type: RecordType,
    pub title: String,
    pub folder: String,
    pub favorite: bool,
    pub created_at: i64,
    pub modified_at: i64,
    pub used_at: Option<i64>,
    pub use_count: i64,
    pub deleted_at: Option<i64>,
}

/// Input for creating a record.
#[derive(Debug, Clone)]
pub struct NewRecord {
    pub record_type: RecordType,
    pub title: String,
    pub folder: String,
    pub favorite: bool,
}

impl NewRecord {
    pub fn new(record_type: RecordType, title: impl Into<String>) -> Self {
        NewRecord {
            record_type,
            title: title.into(),
            folder: String::new(),
            favorite: false,
        }
    }

    pub fn in_folder(mut self, folder: impl Into<String>) -> Self {
        self.folder = folder.into();
        self
    }
}

/// Filter for listing records.
#[derive(Debug, Clone, Default)]
pub struct RecordFilter {
    pub record_type: Option<RecordType>,
    pub folder: Option<String>,
    pub tag: Option<String>,
    pub favorites_only: bool,
    /// When false (the default), soft-deleted records are excluded.
    pub include_deleted: bool,
    /// When true, ONLY soft-deleted records are returned (the trash view).
    pub only_deleted: bool,
    pub limit: Option<u32>,
}
