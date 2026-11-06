use forge_command::{risk, sast, ScanConfig, ScanReport};
use std::path::Path;
#[test]
fn vulnerable_fixture_has_findings() {
    let r = sast::scan(
        Path::new("tests/fixtures/vulnerable_app"),
        &ScanConfig::default(),
    )
    .unwrap();
    assert!(r.findings.iter().any(|f| f.id == "SQL-001"));
    assert!(r.findings.iter().any(|f| f.id == "SEC-001"));
}
#[test]
fn secure_fixture_is_clean() {
    let r = sast::scan(
        Path::new("tests/fixtures/secure_app"),
        &ScanConfig::default(),
    )
    .unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(risk::evaluate(&r).grade, 'A');
}
#[test]
fn incomplete_scan_not_graded() {
    let r = ScanReport {
        findings: vec![],
        files_scanned: 0,
        files_skipped: 0,
        parse_errors: 0,
    };
    assert_eq!(risk::evaluate(&r).grade, 'N');
}
#[test]
fn policy_rejects_traversal() {
    assert!(forge_command::governance::check(
        Some(Path::new("src/../secrets")),
        None,
        &Default::default()
    )
    .is_err());
}
#[test]
fn remote_dast_rejected() {
    assert!(
        forge_command::dast::validate_target("https://example.com", &Default::default()).is_err()
    );
}
