pub mod cmd;
pub mod dast;
pub mod governance;
pub mod risk;
pub mod sast;
pub mod ui;

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
impl Severity {
    pub fn weight(self) -> f64 {
        match self {
            Self::Critical => 10.0,
            Self::High => 6.0,
            Self::Medium => 3.0,
            Self::Low => 1.0,
            Self::Info => 0.0,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub title: String,
    pub location: String,
    pub detail: String,
    pub remediation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub parse_errors: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradeReport {
    pub grade: char,
    pub score: u8,
    pub findings: usize,
    pub coverage_note: String,
}
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub scan: ScanConfig,
    pub dast: DastConfig,
    pub governance: GovernanceConfig,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub max_file_bytes: u64,
    pub exclude: Vec<String>,
}
impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 1_048_576,
            exclude: vec!["node_modules".into(), "target".into(), "dist".into()],
        }
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DastConfig {
    pub max_requests: usize,
    pub max_concurrency: usize,
    pub timeout_ms: u64,
    pub allow_hosts: Vec<String>,
}
impl Default for DastConfig {
    fn default() -> Self {
        Self {
            max_requests: 12,
            max_concurrency: 3,
            timeout_ms: 2000,
            allow_hosts: vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()],
        }
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GovernanceConfig {
    pub allowed_paths: Vec<String>,
    pub blocked_commands: Vec<String>,
}
impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            allowed_paths: vec!["src".into(), "tests".into()],
            blocked_commands: vec!["rm -rf".into(), "git push --force".into()],
        }
    }
}
pub fn load_config(path: &Path) -> Result<Config, String> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_yaml::from_str(&contents).map_err(|e| format!("config {}: {e}", path.display()))
}
