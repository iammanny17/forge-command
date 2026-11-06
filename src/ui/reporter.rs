use crate::{Finding, GradeReport, ScanReport};
pub fn show_findings(findings: &[Finding], json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(findings).map_err(|e| e.to_string())?
        );
    } else {
        for f in findings {
            println!(
                "{:?} [{}] {} @ {}\n  {}\n  Fix: {}",
                f.severity, f.id, f.title, f.location, f.detail, f.remediation
            );
        }
        println!("{} findings", findings.len());
    }
    Ok(())
}
pub fn show_scan(report: &ScanReport, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).map_err(|e| e.to_string())?
        );
        Ok(())
    } else {
        println!(
            "Scanned {} files; skipped {}; parse errors {}",
            report.files_scanned, report.files_skipped, report.parse_errors
        );
        show_findings(&report.findings, false)
    }
}
pub fn show_grade(grade: &GradeReport, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(grade).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "Grade {} | score {}/100 | findings {}\n{}",
            grade.grade, grade.score, grade.findings, grade.coverage_note
        );
    }
    Ok(())
}
