//! Regex-based PII detection scanner.
//!
//! Compiles all PII regexes at startup. Each match returns its label
//! (e.g. "SSN", "CREDIT_CARD", "AWS_KEY") and the matched text.

use crate::rules::loader::PiiRule;
use regex::Regex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PiiError {
    #[error("Invalid PII regex for label '{label}': {source}")]
    InvalidRegex { label: String, source: regex::Error },
}

/// A PII detection match.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PiiMatch {
    /// PII category (e.g. "SSN", "CREDIT_CARD", "AWS_KEY").
    pub label: String,
    /// The matched text.
    pub matched: String,
    /// Byte offset in the input.
    pub offset: usize,
}

/// Compiled PII pattern with its label.
struct CompiledPii {
    label: String,
    regex: Regex,
}

/// PII scanner with pre-compiled regexes.
pub struct PiiScanner {
    patterns: Vec<CompiledPii>,
}

impl PiiScanner {
    /// Compile PII rules into a scanner.
    pub fn new(rules: &[PiiRule]) -> Result<Self, PiiError> {
        let mut patterns = Vec::with_capacity(rules.len());
        for rule in rules {
            let regex = Regex::new(&rule.pattern).map_err(|e| PiiError::InvalidRegex {
                label: rule.label.clone(),
                source: e,
            })?;
            patterns.push(CompiledPii {
                label: rule.label.clone(),
                regex,
            });
        }
        Ok(Self { patterns })
    }

    /// Scan input for PII. Returns all matches across all patterns.
    pub fn scan(&self, input: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        for compiled in &self.patterns {
            for m in compiled.regex.find_iter(input) {
                matches.push(PiiMatch {
                    label: compiled.label.clone(),
                    matched: m.as_str().to_string(),
                    offset: m.start(),
                });
            }
        }
        matches
    }

    /// Number of loaded PII patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::loader::PiiRule;

    fn scanner() -> PiiScanner {
        let rules = vec![
            PiiRule {
                label: "SSN".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
            },
            PiiRule {
                label: "CREDIT_CARD".into(),
                pattern: r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b".into(),
            },
            PiiRule {
                label: "EMAIL".into(),
                pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".into(),
            },
            PiiRule {
                label: "AWS_KEY".into(),
                pattern: r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b".into(),
            },
            PiiRule {
                label: "GITHUB_TOKEN".into(),
                pattern: r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b".into(),
            },
            PiiRule {
                label: "OPENAI_KEY".into(),
                pattern: r"\bsk-[a-zA-Z0-9]{20,}\b".into(),
            },
            PiiRule {
                label: "PRIVATE_KEY".into(),
                pattern: r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".into(),
            },
        ];
        PiiScanner::new(&rules).unwrap()
    }

    #[test]
    fn detects_ssn() {
        let s = scanner();
        let matches = s.scan("My SSN is 123-45-6789");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "SSN");
        assert_eq!(matches[0].matched, "123-45-6789");
    }

    #[test]
    fn detects_credit_card() {
        let s = scanner();
        let matches = s.scan("Card: 4111111111111111");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "CREDIT_CARD");
    }

    #[test]
    fn detects_email() {
        let s = scanner();
        let matches = s.scan("Contact user@example.com for details");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "EMAIL");
    }

    #[test]
    fn detects_aws_key() {
        let s = scanner();
        let matches = s.scan("key: AKIAIOSFODNN7EXAMPLE");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "AWS_KEY");
    }

    #[test]
    fn detects_github_token() {
        let s = scanner();
        let token = format!("ghp_{}", "a".repeat(40));
        let matches = s.scan(&format!("Token: {token}"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "GITHUB_TOKEN");
    }

    #[test]
    fn detects_private_key() {
        let s = scanner();
        let matches = s.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "PRIVATE_KEY");
    }

    #[test]
    fn no_false_positive_on_clean_text() {
        let s = scanner();
        let matches = s.scan("The capital of France is Paris. It has about 2 million people.");
        assert!(matches.is_empty());
    }

    #[test]
    fn detects_multiple_pii_types() {
        let s = scanner();
        let matches = s.scan("SSN: 123-45-6789, email: test@example.com");
        assert_eq!(matches.len(), 2);
    }
}
