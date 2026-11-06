use crate::{dast, ui, DastConfig};
pub fn run(url: &str, cfg: &DastConfig, json: bool) -> Result<(), String> {
    let findings = dast::run(url, cfg)?;
    ui::reporter::show_findings(&findings, json)
}
