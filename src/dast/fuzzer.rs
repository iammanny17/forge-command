use crate::{DastConfig, Finding, Severity};
use reqwest::blocking::Client;
use url::Url;
pub fn probe(client: &Client, base: &Url, cfg: &DastConfig) -> Result<Vec<Finding>, String> {
    let mut out = vec![];
    let budget = cfg
        .max_requests
        .saturating_sub(1)
        .min(crate::dast::payloads::CANARIES.len());
    for canary in crate::dast::payloads::CANARIES.iter().take(budget) {
        let mut url = base.clone();
        url.query_pairs_mut().append_pair("forge_probe", canary);
        let response = client
            .get(url)
            .send()
            .map_err(|e| format!("probe request failed: {e}"))?;
        let status = response.status();
        let body = response.text().unwrap_or_default();
        if status.is_success() && body.contains(canary) {
            out.push(Finding {id:"DAST-REFLECT-001".into(),severity:Severity::Info,confidence:0.95,title:"Canary reflected in response".into(),location:base.to_string(),detail:"Harmless query canary appears in HTTP response; reflection alone is not XSS or injection.".into(),remediation:"Review output encoding and contextual escaping if the reflection is user-controlled.".into()});
            break;
        }
    }
    Ok(out)
}
