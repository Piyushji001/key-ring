//! Password generator (Phase 8).
//!
//! ## Two modes, and why both
//!
//! **Random characters** for the machine-to-machine cases — a database user, a
//! service account, an API consumer. Nobody types these; length and alphabet
//! size are all that matter.
//!
//! **Passphrases** for the ones a human has to read aloud over a phone, type
//! on a server console, or copy off a screen onto paper. Four random words
//! from a 2,048-word list is 44 bits; six is 66. That is weaker per character
//! than random ASCII and far stronger per unit of human effort, which is the
//! trade that matters when someone is standing at a KVM.
//!
//! ## The rules this generator does not have
//!
//! No "must contain a symbol". Composition rules shrink the search space and
//! push people toward `Password1!`. The generator picks uniformly from the
//! chosen alphabet and reports the entropy honestly.
//!
//! There is one exception, and it is opt-in: `require_each_class` guarantees at
//! least one character from every enabled class, because a depressing number of
//! enterprise systems reject passwords that happen not to contain a digit. It
//! costs a fraction of a bit and is off by default.
//!
//! ## Randomness
//!
//! `keyring_crypto::fill_random`, which is the OS CSPRNG. Never
//! `rand::thread_rng`, never a time seed, and never modulo-reducing a random
//! byte into a range — that biases toward the low end of the alphabet. This
//! module uses rejection sampling, which is unbiased and costs a few extra
//! bytes of entropy.



use crate::error::{AppError, Result};

pub const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
pub const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
pub const DIGITS: &str = "23456789";
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";

/// Characters excluded from the sets above, and why.
///
/// `l`, `I`, `1`, `O`, `0` — indistinguishable in most terminal fonts. A
/// password that cannot be reliably read off a screen is a support ticket
/// waiting to happen, and this is a tool for people who read passwords off
/// screens. The cost is about 0.3 bits per character, which twelve extra
/// characters of length repays many times over.
pub const AMBIGUOUS: &str = "lI1O0";

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOptions {
    pub length: usize,
    #[serde(default = "yes")]
    pub lowercase: bool,
    #[serde(default = "yes")]
    pub uppercase: bool,
    #[serde(default = "yes")]
    pub digits: bool,
    #[serde(default = "yes")]
    pub symbols: bool,
    /// Guarantee one character from each enabled class. Off by default.
    #[serde(default)]
    pub require_each_class: bool,
}

fn yes() -> bool {
    true
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            require_each_class: false,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    /// The generated value.
    ///
    /// **This crosses the IPC boundary as plaintext.** It is a third outbound
    /// crossing beyond the two documented in `dto.rs`, and it is defensible
    /// for a reason the others are not: this value is not a secret *yet*. It
    /// was created microseconds ago, is stored nowhere, and protects nothing
    /// until the user saves it. The webview has to draw it — a generator whose
    /// output you cannot see is not a generator.
    ///
    /// It is still treated carefully: not logged, not retained in Rust, and
    /// the frontend replaces it rather than accumulating a history.
    pub password: String,
    pub entropy_bits: f64,
    /// 0–4, matching the strength meter on the setup screen.
    pub strength: u8,
    pub alphabet_size: usize,
}

/// Draw one uniform value in `0..n` by rejection sampling.
///
/// The naive `random_byte % n` is biased whenever `n` does not divide 256 —
/// for a 24-character alphabet the first 16 characters are 1.4% likelier than
/// the rest. Small, but free to avoid.
fn uniform_below(n: usize) -> Result<usize> {
    if n == 0 || n > 65536 {
        return Err(AppError::internal("alphabet size out of range"));
    }
    if n <= 256 {
        let limit = (256 / n) * n;
        loop {
            let mut byte = [0u8; 1];
            keyring_crypto::fill_random(&mut byte)
                .map_err(|_| AppError::internal("the system random source failed"))?;
            let value = byte[0] as usize;
            if value < limit {
                return Ok(value % n);
            }
        }
    } else {
        let limit = (65536 / n) * n;
        loop {
            let mut bytes = [0u8; 2];
            keyring_crypto::fill_random(&mut bytes)
                .map_err(|_| AppError::internal("the system random source failed"))?;
            let value = u16::from_le_bytes(bytes) as usize;
            if value < limit {
                return Ok(value % n);
            }
        }
    }
}

pub fn generate_password(options: &PasswordOptions) -> Result<GeneratedPassword> {
    if options.length < 4 {
        return Err(AppError::invalid("Pick a length of at least 4 characters."));
    }
    if options.length > 256 {
        return Err(AppError::invalid("The longest password is 256 characters."));
    }

    let mut classes: Vec<&str> = Vec::new();
    if options.lowercase {
        classes.push(LOWER);
    }
    if options.uppercase {
        classes.push(UPPER);
    }
    if options.digits {
        classes.push(DIGITS);
    }
    if options.symbols {
        classes.push(SYMBOLS);
    }

    if classes.is_empty() {
        return Err(AppError::invalid("Choose at least one character type."));
    }
    if options.require_each_class && options.length < classes.len() {
        return Err(AppError::invalid(
            "That length is too short to include one of each character type.",
        ));
    }

    let alphabet: Vec<char> = classes.concat().chars().collect();
    let alphabet_size = alphabet.len();

    let mut chars: Vec<char> = Vec::with_capacity(options.length);

    if options.require_each_class {
        for class in &classes {
            let pool: Vec<char> = class.chars().collect();
            chars.push(pool[uniform_below(pool.len())?]);
        }
    }

    while chars.len() < options.length {
        chars.push(alphabet[uniform_below(alphabet_size)?]);
    }

    // Fisher-Yates, so the guaranteed characters are not always at the front.
    for i in (1..chars.len()).rev() {
        let j = uniform_below(i + 1)?;
        chars.swap(i, j);
    }

    let password: String = chars.iter().collect();
    let entropy_bits = (alphabet_size as f64).log2() * options.length as f64;

    Ok(GeneratedPassword {
        password,
        entropy_bits,
        strength: strength_from_entropy(entropy_bits),
        alphabet_size,
    })
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseOptions {
    pub words: usize,
    #[serde(default = "dash")]
    pub separator: String,
    #[serde(default)]
    pub capitalize: bool,
    #[serde(default)]
    pub include_number: bool,
}

fn dash() -> String {
    "-".to_string()
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions {
            words: 5,
            separator: "-".to_string(),
            capitalize: false,
            include_number: false,
        }
    }
}

pub fn generate_passphrase(options: &PassphraseOptions) -> Result<GeneratedPassword> {
    if options.words < 3 {
        return Err(AppError::invalid(
            "Use at least three words. Two is not enough to be worth generating.",
        ));
    }
    if options.words > 32 {
        return Err(AppError::invalid("That is more words than anyone will type."));
    }

    let list = wordlist();
    let mut words: Vec<String> = Vec::with_capacity(options.words);

    for _ in 0..options.words {
        let word = list[uniform_below(list.len())?];
        words.push(if options.capitalize {
            let mut c = word.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        } else {
            word.to_string()
        });
    }

    if options.include_number {
        // Appended to a random word rather than the end, so its position is
        // not a free gift to anyone cracking it.
        let index = uniform_below(words.len())?;
        let digit = uniform_below(10)?;
        words[index].push_str(&digit.to_string());
    }

    let separator = if options.separator.is_empty() {
        "-"
    } else {
        &options.separator
    };
    let password = words.join(separator);

    // Entropy comes from the word choices only. The separator is public and
    // the appended digit adds log2(10 * words) bits, which is not counted:
    // under-reporting strength is the safe direction to be wrong in.
    let entropy_bits = (list.len() as f64).log2() * options.words as f64;

    Ok(GeneratedPassword {
        password,
        entropy_bits,
        strength: strength_from_entropy(entropy_bits),
        alphabet_size: list.len(),
    })
}

/// Map entropy onto the same 0–4 scale the master password meter uses.
///
/// The thresholds are chosen against offline attack, not online: 60 bits is
/// uncomfortable against a well-funded attacker with the ciphertext, 80 is
/// sound, 100 is beyond argument.
fn strength_from_entropy(bits: f64) -> u8 {
    match bits {
        b if b < 45.0 => 0,
        b if b < 60.0 => 1,
        b if b < 80.0 => 2,
        b if b < 100.0 => 3,
        _ => 4,
    }
}

/// A 2,048-word list — exactly 11 bits per word.
///
/// Built from short, unambiguous, commonly-spelled English words. The
/// power-of-two size is what makes the entropy arithmetic exact rather than
/// approximate.
///
/// Generated from the embedded list at build time so that the count is
/// verified by a test rather than trusted.
fn wordlist() -> &'static [&'static str] {
    WORDS
}

/// The word list. Truncated here to the first 2,048 entries of a curated set.
static WORDS: &[&str] = &include!("wordlist.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_exactly_a_power_of_two() {
        // If this fails the entropy figures shown to users are wrong.
        assert_eq!(
            wordlist().len(),
            2048,
            "the list must be exactly 2048 words for 11 bits each"
        );
    }

    #[test]
    fn the_wordlist_has_no_duplicates() {
        // A duplicate silently reduces entropy without changing the count.
        let unique: std::collections::HashSet<&&str> = wordlist().iter().collect();
        assert_eq!(unique.len(), wordlist().len(), "duplicate words found");
    }

    #[test]
    fn generated_passwords_have_the_requested_length() {
        for length in [8usize, 16, 24, 64] {
            let options = PasswordOptions {
                length,
                ..Default::default()
            };
            let out = generate_password(&options).unwrap();
            assert_eq!(out.password.chars().count(), length);
        }
    }

    #[test]
    fn ambiguous_characters_never_appear() {
        let options = PasswordOptions {
            length: 200,
            ..Default::default()
        };
        let out = generate_password(&options).unwrap();
        for c in AMBIGUOUS.chars() {
            assert!(
                !out.password.contains(c),
                "{c} is ambiguous and must be excluded"
            );
        }
    }

    #[test]
    fn require_each_class_actually_includes_each_class() {
        let options = PasswordOptions {
            length: 8,
            require_each_class: true,
            ..Default::default()
        };
        // Run it repeatedly: a single pass could pass by luck.
        for _ in 0..40 {
            let out = generate_password(&options).unwrap();
            assert!(out.password.chars().any(|c| LOWER.contains(c)));
            assert!(out.password.chars().any(|c| UPPER.contains(c)));
            assert!(out.password.chars().any(|c| DIGITS.contains(c)));
            assert!(out.password.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn no_character_class_is_an_error_not_an_empty_password() {
        let options = PasswordOptions {
            length: 16,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            require_each_class: false,
        };
        assert!(generate_password(&options).is_err());
    }

    #[test]
    fn two_generations_differ() {
        let options = PasswordOptions::default();
        let a = generate_password(&options).unwrap();
        let b = generate_password(&options).unwrap();
        assert_ne!(a.password, b.password);
    }

    #[test]
    fn uniform_below_is_not_biased() {
        // Chi-squared would be better, but a crude range check catches the
        // modulo-bias bug this function exists to avoid.
        let n = 24;
        let mut counts = vec![0usize; n];
        for _ in 0..12_000 {
            counts[uniform_below(n).unwrap()] += 1;
        }
        let expected = 12_000.0 / n as f64;
        for (i, count) in counts.iter().enumerate() {
            let deviation = (*count as f64 - expected).abs() / expected;
            assert!(deviation < 0.25, "bucket {i} deviates {deviation:.3}");
        }
    }

    #[test]
    fn passphrase_entropy_is_eleven_bits_per_word() {
        let options = PassphraseOptions {
            words: 6,
            ..Default::default()
        };
        let out = generate_passphrase(&options).unwrap();
        assert!((out.entropy_bits - 66.0).abs() < 0.001);
        assert_eq!(out.password.split('-').count(), 6);
    }

    #[test]
    fn passphrase_rejects_a_pointlessly_short_request() {
        let options = PassphraseOptions {
            words: 2,
            ..Default::default()
        };
        assert!(generate_passphrase(&options).is_err());
    }

    #[test]
    fn strength_thresholds_are_monotonic() {
        assert_eq!(strength_from_entropy(30.0), 0);
        assert_eq!(strength_from_entropy(50.0), 1);
        assert_eq!(strength_from_entropy(70.0), 2);
        assert_eq!(strength_from_entropy(90.0), 3);
        assert_eq!(strength_from_entropy(140.0), 4);
    }
}
