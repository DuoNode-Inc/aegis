//! Parse .rules files from disk.
//!
//! Supports three formats:
//! - injection.rules: one pattern per line
//! - pii.rules: LABEL:regex per line
//! - endpoints.rules: one hostname per line
//!
//! All formats: `#` comments, empty lines ignored.

use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RulesError {
    #[error("Failed to read rules file '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("Invalid PII rule at line {line}: expected LABEL:regex, got '{content}'")]
    InvalidPiiRule { line: usize, content: String },
}

/// A labeled regex pattern for PII detection.
#[derive(Debug, Clone)]
pub struct PiiRule {
    pub label: String,
    pub pattern: String,
}

/// Load plain-text patterns (injection, endpoints).
/// Returns non-empty, non-comment lines.
pub fn load_patterns(path: &Path) -> Result<Vec<String>, RulesError> {
    let content = std::fs::read_to_string(path).map_err(|e| RulesError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_patterns_skips_comments_and_blanks() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            "# comment\n\npattern one\n  # indented comment\n\npattern two\n"
        )
        .unwrap();
        let patterns = load_patterns(tmp.path()).unwrap();
        assert_eq!(patterns, vec!["pattern one", "pattern two"]);
    }

    #[test]
    fn load_patterns_trims_whitespace() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "  hello world  \n").unwrap();
        let patterns = load_patterns(tmp.path()).unwrap();
        assert_eq!(patterns, vec!["hello world"]);
    }

    #[test]
    fn load_patterns_missing_file_errors() {
        let result = load_patterns(Path::new("/nonexistent/rules.txt"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("/nonexistent/rules.txt"));
    }

    #[test]
    fn load_patterns_empty_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "# only comments\n\n# and blanks\n").unwrap();
        let patterns = load_patterns(tmp.path()).unwrap();
        assert!(patterns.is_empty());
    }

    #[test]
    fn load_pii_rules_parses_label_pattern() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "SSN:\\b\\d{{3}}-\\d{{2}}-\\d{{4}}\\b\nEMAIL:foo@bar\n").unwrap();
        let rules = load_pii_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].label, "SSN");
        assert!(rules[0].pattern.contains("\\d"));
        assert_eq!(rules[1].label, "EMAIL");
        assert_eq!(rules[1].pattern, "foo@bar");
    }

    #[test]
    fn load_pii_rules_skips_comments() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "# header\nSSN:pattern\n# footer\n").unwrap();
        let rules = load_pii_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn load_pii_rules_invalid_format_errors() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "no colon here\n").unwrap();
        let result = load_pii_rules(tmp.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("line 1"));
        assert!(err.to_string().contains("no colon here"));
    }

    #[test]
    fn load_pii_rules_handles_colons_in_pattern() {
        // Pattern itself may contain colons (e.g., regex for URLs)
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "URL:https?://[a-z]+\n").unwrap();
        let rules = load_pii_rules(tmp.path()).unwrap();
        assert_eq!(rules[0].label, "URL");
        assert_eq!(rules[0].pattern, "https?://[a-z]+");
    }

    #[test]
    fn load_actual_injection_rules() {
        let rules_path = Path::new("rules/injection.rules");
        if rules_path.exists() {
            let patterns = load_patterns(rules_path).unwrap();
            assert!(
                patterns.len() >= 100,
                "Expected 100+ injection patterns, got {}",
                patterns.len()
            );
        }
    }

    #[test]
    fn load_actual_pii_rules() {
        let rules_path = Path::new("rules/pii.rules");
        if rules_path.exists() {
            let rules = load_pii_rules(rules_path).unwrap();
            assert!(
                rules.len() >= 20,
                "Expected 20+ PII rules, got {}",
                rules.len()
            );
        }
    }
}

/// Load labeled PII rules (LABEL:regex format).
pub fn load_pii_rules(path: &Path) -> Result<Vec<PiiRule>, RulesError> {
    let content = std::fs::read_to_string(path).map_err(|e| RulesError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut rules = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((label, pattern)) = trimmed.split_once(':') else {
            return Err(RulesError::InvalidPiiRule {
                line: i + 1,
                content: trimmed.to_string(),
            });
        };
        rules.push(PiiRule {
            label: label.trim().to_string(),
            pattern: pattern.trim().to_string(),
        });
    }

    Ok(rules)
}
