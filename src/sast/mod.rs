pub mod crawler;
pub mod rules;
pub mod taint_engine;
use crate::{ScanConfig, ScanReport};
use std::path::Path;
pub fn scan(root: &Path, cfg: &ScanConfig) -> Result<ScanReport, String> {
    let paths = crawler::collect(root, cfg)?;
    let mut report = ScanReport {
        findings: vec![],
        files_scanned: 0,
        files_skipped: 0,
        parse_errors: 0,
    };
    for path in paths {
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        if meta.len() > cfg.max_file_bytes {
            report.files_skipped += 1;
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        let Ok(text) = String::from_utf8(bytes) else {
            report.files_skipped += 1;
            continue;
        };
        let (findings, has_error) = taint_engine::analyze(&path, &text);
        report.files_scanned += 1;
        report.parse_errors += usize::from(has_error);
        report.findings.extend(findings);
    }
    Ok(report)
}
