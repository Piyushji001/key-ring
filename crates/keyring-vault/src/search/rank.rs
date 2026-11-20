//! Scoring: fuzzy match quality, combined with recency and frequency (FR-4.2).
//!
//! ## Why this is hand-written
//!
//! Structure §3 lists `nucleo-matcher`. A subsequence scorer is about sixty
//! lines, has no API to get wrong, and is trivially testable - and search
//! ranking is a place where "good enough and understood" beats "better and
//! opaque". Swap in nucleo later if ranking ever feels wrong; the interface
//! here is one function.
//!
//! ## The ranking argument
//!
//! A DevOps engineer types two or three characters and expects the thing they
//! used yesterday. Match quality alone would rank a perfect match on a record
//! last touched two years ago above a good match on the server they SSH into
//! daily. So recency and frequency are additive bonuses on top of match score,
//! never multipliers - a bad match must not float up just because it is popular.

use crate::model::RecordType;

/// One result, ready for the UI. Carries no secret: `matched_field` is a field
/// *name*, and `matched_context` is only ever drawn from non-secret values.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub record_id: String,
    pub title: String,
    pub record_type: RecordType,
    pub folder: String,
    pub favorite: bool,
    pub score: i64,
    /// Which field produced the match, so the UI can say why this is here.
    pub matched_field: Option<String>,
    pub matched_context: Option<String>,
}

/// Score `needle` against `haystack`. Higher is better; `None` means no match.
///
/// Rewards, in order of weight: an exact match, a prefix match, matches at word
/// boundaries, and runs of consecutive characters. Penalises gaps and long
/// haystacks, so "db" prefers "db-01" over "not-a-database-really".
pub fn fuzzy_score(needle: &str, haystack: &str) -> Option<i64> {
    if needle.is_empty() {
        return Some(0);
    }
    let hay = haystack.to_ascii_lowercase();
    let need = needle.to_ascii_lowercase();

    if hay == need {
        return Some(1000);
    }
    if hay.starts_with(&need) {
        return Some(800 - (hay.len() as i64 - need.len() as i64).min(200));
    }
    if let Some(pos) = hay.find(&need) {
        let at_boundary = pos > 0
            && hay
                .as_bytes()
                .get(pos - 1)
                .map(|c| matches!(c, b' ' | b'-' | b'_' | b'.' | b'/' | b'@' | b':'))
                .unwrap_or(false);
        let bonus = if at_boundary { 120 } else { 0 };
        return Some(600 + bonus - (pos as i64).min(200));
    }

    // Subsequence: every needle character must appear in order.
    let mut score: i64 = 200;
    let mut hay_iter = hay.char_indices().peekable();
    let mut last_index: Option<usize> = None;
    let mut consecutive = 0i64;

    for ch in need.chars() {
        let mut found = None;
        for (i, hc) in hay_iter.by_ref() {
            if hc == ch {
                found = Some(i);
                break;
            }
        }
        let i = found?;

        match last_index {
            Some(prev) if i == prev + 1 => {
                consecutive += 1;
                score += 15 + consecutive * 5;
            }
            Some(prev) => {
                consecutive = 0;
                score -= ((i - prev) as i64).min(20);
            }
            None => {
                // Matching near the start is worth something.
                score += if i == 0 { 40 } else { 0 };
            }
        }
        last_index = Some(i);
    }

    score -= (hay.len() as i64 / 12).min(30);
    Some(score.max(1))
}

/// Recency bonus. Used today is worth a lot; used last year is worth nothing.
pub fn recency_bonus(used_at: Option<i64>, now: i64) -> i64 {
    let Some(used) = used_at else { return 0 };
    let age_days = ((now - used).max(0)) / 86_400;
    match age_days {
        0 => 220,
        1 => 180,
        2..=6 => 130,
        7..=29 => 70,
        30..=89 => 30,
        _ => 0,
    }
}

/// Frequency bonus, deliberately logarithmic: the difference between 1 and 10
/// uses matters, between 500 and 600 it does not.
pub fn frequency_bonus(use_count: i64) -> i64 {
    match use_count {
        0 => 0,
        1..=2 => 20,
        3..=9 => 50,
        10..=49 => 90,
        _ => 120,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_beats_prefix_beats_substring_beats_subsequence() {
        let exact = fuzzy_score("prod", "prod").unwrap();
        let prefix = fuzzy_score("prod", "prod-web-01").unwrap();
        let substring = fuzzy_score("web", "prod-web-01").unwrap();
        let subseq = fuzzy_score("pw1", "prod-web-01").unwrap();
        assert!(exact > prefix, "{exact} > {prefix}");
        assert!(prefix > substring, "{prefix} > {substring}");
        assert!(substring > subseq, "{substring} > {subseq}");
    }

    #[test]
    fn missing_characters_do_not_match() {
        assert!(fuzzy_score("zzz", "prod-web-01").is_none());
    }

    #[test]
    fn out_of_order_characters_do_not_match() {
        assert!(fuzzy_score("bew", "web").is_none());
    }

    #[test]
    fn shorter_haystacks_win_for_the_same_prefix() {
        let short = fuzzy_score("db", "db-01").unwrap();
        let long = fuzzy_score("db", "db-something-much-longer-here").unwrap();
        assert!(short > long);
    }

    #[test]
    fn word_boundaries_are_rewarded() {
        let boundary = fuzzy_score("web", "prod-web").unwrap();
        let middle = fuzzy_score("web", "prodweb").unwrap();
        assert!(boundary > middle);
    }

    #[test]
    fn recency_decays() {
        let now = 1_800_000_000;
        assert!(recency_bonus(Some(now), now) > recency_bonus(Some(now - 86_400 * 10), now));
        assert_eq!(recency_bonus(None, now), 0);
    }
}
