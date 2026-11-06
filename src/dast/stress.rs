use crate::{DastConfig, Finding, Severity};
use reqwest::blocking::Client;
use url::Url;
pub fn check(client: &Client, url: &Url, cfg: &DastConfig) -> Result<Vec<Finding>, String> {
    // Sequential, capped requests: no denial-of-service or saturation attempts.
    let budget = cfg
        .max_requests
        .saturating_sub(crate::dast::payloads::CANARIES.len())
        .min(6);
    if budget == 0 {
        return Ok(vec![]);
    }
    let mut throttled = 0;
    for _ in 0..budget {
        let response = client
            .get(url.clone())
            .send()
            .map_err(|e| format!("rate-limit check failed: {e}"))?;
        if response.status().as_u16() == 429 {
            throttled += 1;
        }
    }
    let detail = if throttled > 0 {
        format!("Observed {throttled} HTTP 429 responses in {budget} sequential requests.")
    } else {
        format!("No HTTP 429 observed in {budget} sequential requests; this does not establish a missing rate limit.")
    };
    Ok(vec![Finding {
        id: "DAST-RATE-INFO".into(),
        severity: Severity::Info,
        confidence: 1.0,
        title: "Bounded rate-limit observation".into(),
        location: url.to_string(),
        detail,
        remediation:
            "Review server-side rate limits under an explicitly authorized load-testing plan."
                .into(),
    }])
}
