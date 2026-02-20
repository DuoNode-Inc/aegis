//! Supply-chain scanner for dependency introductions and obvious malware patterns.
//!
//! This is designed for pre-commit / CI gating when new packages are introduced.

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: &'static str,
    pub path: PathBuf,
    pub line: usize,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub scanned_files: usize,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn high_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub repo_path: PathBuf,
    pub staged_only: bool,
}

pub fn scan_repo(opts: &ScanOptions) -> Result<ScanReport> {
    let root = opts.repo_path.canonicalize().with_context(|| {
        format!(
            "Failed to resolve repo path: {}",
            opts.repo_path.to_string_lossy()
        )
    })?;

    let candidates = if opts.staged_only {
        staged_files(&root)?
    } else {
        collect_repo_files(&root)?
    };

    let mut findings = Vec::new();
    let mut scanned_files = 0usize;

    for path in candidates {
        if !path.exists() || !path.is_file() {
            continue;
        }
        scanned_files += 1;
        if is_package_json(&path) {
            scan_package_manifest(&path, &mut findings)?;
        }
        if is_code_file(&path) {
            scan_code_file(&path, &mut findings)?;
        }
    }

    Ok(ScanReport {
        scanned_files,
        findings,
    })
}

fn staged_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output()
        .with_context(|| "Failed to run git diff for staged files")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git diff failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).with_context(|| "Invalid UTF-8 from git diff")?;
    let paths = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|rel| repo_root.join(rel))
        .collect();

    Ok(paths)
}

fn collect_repo_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk_dir(root, &mut out)?;
    Ok(out)
}

fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Failed to read dir {}", dir.display()))? {
        let entry = entry.with_context(|| "Failed to read dir entry")?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if name == ".git" || name == "node_modules" || name == "target" || name == "dist" {
            continue;
        }

        let ty = entry
            .file_type()
            .with_context(|| format!("Failed to get file type for {}", path.display()))?;
        if ty.is_dir() {
            walk_dir(&path, out)?;
        } else if ty.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn is_package_json(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == "package.json")
        .unwrap_or(false)
}

fn is_code_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ts")
            | Some("tsx")
            | Some("js")
            | Some("jsx")
            | Some("mjs")
            | Some("cjs")
            | Some("mts")
            | Some("cts")
    )
}

fn scan_package_manifest(path: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let parsed: Value =
        serde_json::from_str(&raw).with_context(|| format!("Invalid JSON in {}", path.display()))?;

    let risky_names: HashSet<&str> = HashSet::from(["axos"]);
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(map) = parsed.get(section).and_then(Value::as_object) {
            for dep in map.keys() {
                if risky_names.contains(dep.as_str()) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "suspicious-dependency",
                        path: path.to_path_buf(),
                        line: line_number_of(&raw, &format!("\"{dep}\"")),
                        detail: format!(
                            "Dependency '{dep}' is suspicious (possible typo-squat). Investigate before merge."
                        ),
                    });
                }
            }
        }
    }

    let install_script_pattern =
        Regex::new(r"(curl\s|wget\s|bash\s+-c|powershell|node\s+-e)").with_context(|| "Bad regex")?;
    if let Some(scripts) = parsed.get("scripts").and_then(Value::as_object) {
        for hook in ["preinstall", "install", "postinstall", "prepare"] {
            if let Some(script) = scripts.get(hook).and_then(Value::as_str) {
                if install_script_pattern.is_match(script) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "install-hook",
                        path: path.to_path_buf(),
                        line: line_number_of(&raw, &format!("\"{hook}\"")),
                        detail: format!(
                            "Install hook '{hook}' runs shell-like command: {script}"
                        ),
                    });
                }
            }
        }
    }

    Ok(())
}

fn scan_code_file(path: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut first = FirstPassSignals::default();

    // Pass 1: primitive signal collection.
    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;

        if line.contains("new Function(") {
            first.new_function_line.get_or_insert(line_no);
        }
        if line.contains("eval(") {
            first.eval_line.get_or_insert(line_no);
        }
        if line.contains("...process.env") {
            first.env_spread_line.get_or_insert(line_no);
        }
        if line.contains("axios.post(")
            || line.contains("axios.get(")
            || line.contains("fetch(")
            || line.contains("http://")
            || line.contains("https://")
        {
            first.network_line.get_or_insert(line_no);
        }
        if line.contains("atob(")
            || line.contains("Buffer.from(")
            || line.contains("base64")
            || line.contains("aHR0c")
        {
            first.decoding_line.get_or_insert(line_no);
        }
        if line.contains("createRequire(") || line.contains("require)") {
            first.require_bridge_line.get_or_insert(line_no);
        }
        if line.contains("child_process")
            || line.contains("exec(")
            || line.contains("spawn(")
            || line.contains("fork(")
        {
            first.process_exec_line.get_or_insert(line_no);
        }
    }

    // Pass 2: inference from correlated signals.
    infer_findings(path, &first, findings);

    // Keep medium process-exec as standalone operational signal.
    if let Some(line) = first.process_exec_line {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "process-exec",
            path: path.to_path_buf(),
            line,
            detail: "Process execution primitive present; verify trusted usage".into(),
        });
    }
    Ok(())
}

#[derive(Default)]
struct FirstPassSignals {
    new_function_line: Option<usize>,
    eval_line: Option<usize>,
    env_spread_line: Option<usize>,
    network_line: Option<usize>,
    decoding_line: Option<usize>,
    require_bridge_line: Option<usize>,
    process_exec_line: Option<usize>,
}

fn infer_findings(path: &Path, s: &FirstPassSignals, findings: &mut Vec<Finding>) {
    // Very strong pattern: env spread to network sink.
    if let (Some(env_line), Some(_net_line)) = (s.env_spread_line, s.network_line) {
        findings.push(Finding {
            severity: Severity::High,
            category: "env-exfiltration",
            path: path.to_path_buf(),
            line: env_line,
            detail: "Inferred env exfiltration path: environment spread with network sink".into(),
        });
    }

    // Strong malicious chain: dynamic function + remote/decode + require bridge.
    if let Some(func_line) = s.new_function_line {
        let strong_chain =
            s.network_line.is_some() && (s.decoding_line.is_some() || s.require_bridge_line.is_some());
        if strong_chain {
            findings.push(Finding {
                severity: Severity::High,
                category: "dynamic-code-exec",
                path: path.to_path_buf(),
                line: func_line,
                detail:
                    "Inferred remote code execution chain: dynamic function combined with network/decode signals"
                        .into(),
            });
        } else {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "dynamic-code-exec",
                path: path.to_path_buf(),
                line: func_line,
                detail:
                    "Dynamic code execution primitive detected (new Function). Manual review required."
                        .into(),
            });
        }
    }

    if let Some(eval_line) = s.eval_line {
        findings.push(Finding {
            severity: Severity::High,
            category: "dynamic-code-exec",
            path: path.to_path_buf(),
            line: eval_line,
            detail: "Dynamic code execution via eval(...)".into(),
        });
    }
}

fn line_number_of(text: &str, needle: &str) -> usize {
    text.lines()
        .enumerate()
        .find_map(|(idx, line)| line.contains(needle).then_some(idx + 1))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::{scan_repo, ScanOptions, Severity};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn catches_fintrust_style_indicators() {
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();

        fs::write(
            root.join("package.json"),
            r#"{
  "dependencies": { "axos": "^0.0.1" }
}"#,
        )
        .expect("write package");

        fs::create_dir_all(root.join("server/src")).expect("mkdir");
        fs::write(
            root.join("server/src/loans.routes.ts"),
            r#"const x = new Function('require', payload);
axios.post(api, { ...process.env }, { headers: { 'x': 'y' } });
"#,
        )
        .expect("write ts");

        let report = scan_repo(&ScanOptions {
            repo_path: root.to_path_buf(),
            staged_only: false,
        })
        .expect("scan");

        assert!(
            report.findings.iter().any(|f| {
                f.category == "suspicious-dependency" && f.severity == Severity::High
            }),
            "expected suspicious dependency finding"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "dynamic-code-exec" && f.severity == Severity::High),
            "expected dynamic code exec finding"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "env-exfiltration" && f.severity == Severity::High),
            "expected env exfiltration finding"
        );
    }

    #[test]
    fn isolated_new_function_is_medium_on_second_pass() {
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();

        fs::write(
            root.join("index.js"),
            r#"function buildHandler(code){ return new Function("x", code); }"#,
        )
        .expect("write js");

        let report = scan_repo(&ScanOptions {
            repo_path: root.to_path_buf(),
            staged_only: false,
        })
        .expect("scan");

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "dynamic-code-exec" && f.severity == Severity::Medium),
            "expected medium finding for isolated new Function"
        );
        assert_eq!(
            report.high_count(),
            0,
            "isolated new Function should not auto-escalate to high"
        );
    }
}
