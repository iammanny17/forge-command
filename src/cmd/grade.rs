use crate::{risk, sast, ui, ScanConfig};
use std::path::Path;
pub fn run(path: &Path, cfg: &ScanConfig, json: bool) -> Result<(), String> {
    let scan = sast::scan(path, cfg)?;
    let grade = risk::evaluate(&scan);
    ui::reporter::show_grade(&grade, json)
}
