use crate::ScanConfig;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
pub fn collect(root: &Path, cfg: &ScanConfig) -> Result<Vec<PathBuf>, String> {
    if !root.exists() {
        return Err(format!("path not found: {}", root.display()));
    }
    let mut files = Vec::new();
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true);
    for item in builder.build() {
        let item = item.map_err(|e| e.to_string())?;
        if !item.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = item.path();
        if path.components().any(|c| {
            cfg.exclude
                .iter()
                .any(|x| c.as_os_str() == std::ffi::OsStr::new(x))
        }) {
            continue;
        }
        if matches!(
            path.extension().and_then(|x| x.to_str()),
            Some("py" | "js" | "jsx" | "ts" | "tsx" | "go" | "cpp" | "cc" | "cxx" | "hpp" | "h")
        ) {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}
