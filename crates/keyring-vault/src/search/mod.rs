//! Search: the feature the product lives or dies by.
//!
//! UC-01 requires hotkey to clipboard in under two seconds, and FR-4.3 requires
//! results in under 50 ms across 10,000 records. Both are met the same way: the
//! index is built once on unlock and held in memory, so a query never touches
//! SQLite.
//!
//! ## What is searchable
//!
//! Titles, folders, tags, and every non-secret field value: usernames,
//! hostnames, ports, URLs, providers, attachment filenames. FR-4.1 also lists
//! note bodies, and those are encrypted - see `index.rs` for how that is
//! handled and what it costs.
//!
//! Secret values are never indexed. Searching for a password by its content is
//! not a feature, it is a leak.

pub mod index;
pub mod query;
pub mod rank;

pub use index::{IndexEntry, SearchIndex};
pub use query::{ParsedQuery, Scope};
pub use rank::SearchHit;
