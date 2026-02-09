//! Lightweight tokenizer adapter for classifier input preparation.
//!
//! For v0.2 scaffolding, we use a deterministic whitespace tokenizer and
//! enforce a hard cap of 512 tokens. This will later be replaced by a
//! model-specific tokenizer backend.

/// Maximum number of tokens passed to the classifier.
pub const MAX_CLASSIFIER_TOKENS: usize = 512;

/// Tokenize text and return up to `MAX_CLASSIFIER_TOKENS` tokens.
pub fn tokenize_for_classifier(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .take(MAX_CLASSIFIER_TOKENS)
        .map(ToString::to_string)
        .collect()
}

/// Build a classifier input string from tokenized text.
pub fn build_classifier_input(input: &str) -> String {
    tokenize_for_classifier(input).join(" ")
}

/// Build deterministic fallback token IDs for classifier models.
///
/// This is used when a model-specific tokenizer is unavailable. IDs are stable
/// across process runs so tests remain deterministic.
#[cfg(any(test, feature = "neural"))]
pub fn fallback_token_ids(input: &str) -> Vec<i64> {
    tokenize_for_classifier(input)
        .into_iter()
        .map(|token| stable_token_id(&token))
        .collect()
}

#[cfg(any(test, feature = "neural"))]
fn stable_token_id(token: &str) -> i64 {
    // 64-bit FNV-1a; mask to positive range for i64 tensor compatibility.
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in token.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash & 0x7fff_ffff_ffff_ffff) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_truncates_to_512() {
        let input = (0..700)
            .map(|i| format!("tok{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let tokens = tokenize_for_classifier(&input);
        assert_eq!(tokens.len(), MAX_CLASSIFIER_TOKENS);
        assert_eq!(tokens[0], "tok0");
        assert_eq!(tokens[511], "tok511");
    }

    #[test]
    fn build_input_preserves_order() {
        let input = "alpha beta gamma";
        assert_eq!(build_classifier_input(input), "alpha beta gamma");
    }

    #[test]
    fn fallback_token_ids_are_deterministic() {
        let input = "alpha beta gamma";
        let first = fallback_token_ids(input);
        let second = fallback_token_ids(input);
        assert_eq!(first, second);
    }

    #[test]
    fn fallback_token_ids_follow_token_limit() {
        let input = (0..700)
            .map(|i| format!("tok{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ids = fallback_token_ids(&input);
        assert_eq!(ids.len(), MAX_CLASSIFIER_TOKENS);
    }
}
