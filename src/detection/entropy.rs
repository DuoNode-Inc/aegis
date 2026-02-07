//! Shannon entropy calculator for detecting encoded/obfuscated data.
//!
//! High entropy (>5.5 bits/byte) in response bodies may indicate
//! base64-encoded data exfiltration or encrypted payloads.
//! Normal English text: ~4.0, base64: ~5.5-6.0, encrypted: ~7.5+

/// Result of entropy analysis.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EntropyResult {
    /// Shannon entropy in bits per byte (0.0 - 8.0).
    pub entropy: f64,
    /// Length of the analyzed input in bytes.
    pub length: usize,
    /// Whether entropy exceeds the configured threshold.
    pub flagged: bool,
}

/// Calculate Shannon entropy of a byte sequence.
pub fn calculate(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Analyze input against the configured threshold and minimum length.
pub fn analyze(data: &[u8], threshold: f64, min_length: usize) -> EntropyResult {
    let length = data.len();
    if length < min_length {
        return EntropyResult {
            entropy: 0.0,
            length,
            flagged: false,
        };
    }

    let entropy = calculate(data);
    EntropyResult {
        entropy,
        length,
        flagged: entropy > threshold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_zero_entropy() {
        assert_eq!(calculate(b""), 0.0);
    }

    #[test]
    fn single_byte_zero_entropy() {
        assert_eq!(calculate(b"aaaa"), 0.0);
    }

    #[test]
    fn two_equally_distributed_bytes() {
        // "abababab" → 2 symbols, each 50% → entropy = 1.0
        let entropy = calculate(b"abababab");
        assert!((entropy - 1.0).abs() < 0.001);
    }

    #[test]
    fn english_text_moderate_entropy() {
        let text = b"The quick brown fox jumps over the lazy dog. \
                     This is a normal sentence with typical English entropy.";
        let entropy = calculate(text);
        // English text typically ~3.5-4.5 bits/byte
        assert!(entropy > 3.0, "entropy {entropy} too low for English");
        assert!(entropy < 5.0, "entropy {entropy} too high for English");
    }

    #[test]
    fn base64_high_entropy() {
        // Simulated base64 data — high entropy
        let b64 = b"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmcg\
                     dGhhdCBzaG91bGQgaGF2ZSBoaWdoZXIgZW50cm9weSB0aGFuIG5vcm1hbCB0\
                     ZXh0LiBMZXQncyBtYWtlIGl0IGxvbmdlciBmb3IgYmV0dGVyIG1lYXN1cmVt\
                     ZW50LiBSYW5kb20gZGF0YTogaDdKOWtMMnBReFZ3";
        let entropy = calculate(b64);
        assert!(entropy > 5.0, "base64 entropy {entropy} should be high");
    }

    #[test]
    fn analyze_skips_short_input() {
        let result = analyze(b"short", 5.5, 100);
        assert!(!result.flagged);
        assert_eq!(result.entropy, 0.0);
    }

    #[test]
    fn analyze_flags_high_entropy() {
        let data: Vec<u8> = (0..=255).cycle().take(256).collect();
        let result = analyze(&data, 5.5, 100);
        assert!(result.flagged, "random bytes should exceed threshold");
        assert!(result.entropy > 7.0);
    }

    #[test]
    fn analyze_passes_normal_text() {
        let text = b"This is a perfectly normal question about how to write \
                     a function in Python that calculates fibonacci numbers. \
                     Can you help me with the implementation?";
        let result = analyze(text, 5.5, 50);
        assert!(!result.flagged);
    }
}
