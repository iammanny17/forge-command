use crate::{GradeReport, ScanReport};
pub fn evaluate(scan: &ScanReport) -> GradeReport {
    let penalty: f64 = scan
        .findings
        .iter()
        .map(|f| f.severity.weight() * f.confidence.clamp(0.0, 1.0))
        .sum();
    let score = (100.0 - penalty).clamp(0.0, 100.0) as u8;
    let incomplete = scan.files_scanned == 0 || scan.files_skipped > 0 || scan.parse_errors > 0;
    let grade = if incomplete {
        'N'
    } else {
        match score {
            90..=100 => 'A',
            80..=89 => 'B',
            70..=79 => 'C',
            60..=69 => 'D',
            _ => 'F',
        }
    };
    let coverage_note = if incomplete {
        format!(
            "Incomplete scan: {} scanned, {} skipped, {} with parse errors; grade N (not rated).",
            scan.files_scanned, scan.files_skipped, scan.parse_errors
        )
    } else {
        "Heuristic SAST-only score; not a security certification or DAST result.".into()
    };
    GradeReport {
        grade,
        score,
        findings: scan.findings.len(),
        coverage_note,
    }
}
