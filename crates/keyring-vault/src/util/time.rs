//! One place that decides what "now" means, so tests can reason about it.

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Format a unix timestamp for CLI output.
pub fn format_unix(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "unknown".to_string(),
    }
}
