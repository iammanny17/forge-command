use crate::{sast, ui, ScanConfig};
use std::path::Path;
pub fn run(path: &Path, cfg: &ScanConfig, json: bool) -> Result<(), String> {
    let report = sast::scan(path, cfg)?;
    ui::reporter::show_scan(&report, json)
}
