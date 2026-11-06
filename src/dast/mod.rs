pub mod fuzzer;
pub mod payloads;
pub mod stress;

use crate::{DastConfig, Finding};
use url::Url;

pub fn validate_target(raw: &str, cfg: &DastConfig) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;

    // Only allow plain HTTP targets.
    if url.scheme() != "http" {
        return Err("only plain HTTP local targets are supported".into());
    }

    // Reject URLs containing credentials.
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL credentials not allowed".into());
    }

    // Extract the target hostname.
    let host = url.host_str().ok_or("target has no host")?;

    // Verify that the hostname is explicitly allowlisted.
    if !cfg.allow_hosts.iter().any(|h| {
        h.trim_matches(&['[', ']'][..])
            .eq_ignore_ascii_case(host.trim_matches(&['[', ']'][..]))
    }) {
        return Err("target host is not allowlisted".into());
    }

    // Enforce safe DAST execution limits.
    if cfg.max_requests == 0
        || cfg.max_requests > 100
        || cfg.max_concurrency == 0
        || cfg.max_concurrency > 4
        || cfg.timeout_ms == 0
        || cfg.timeout_ms > 10_000
    {
        return Err(
            "unsafe DAST config: requests 1..100, concurrency 1..4, timeout 1..10000ms".into(),
        );
    }

    Ok(url)
}

pub fn run(raw: &str, cfg: &DastConfig) -> Result<Vec<Finding>, String> {
    let url = validate_target(raw, cfg)?;

    // Create an HTTP client with a configured timeout.
    // Disable redirects to prevent following requests to other hosts.
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;

    // Execute DAST probes.
    let mut findings = fuzzer::probe(&client, &url, cfg)?;

    // Execute stress checks.
    findings.extend(stress::check(&client, &url, cfg)?);

    Ok(findings)
}
