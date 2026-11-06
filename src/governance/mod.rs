use crate::GovernanceConfig;
use std::path::Path;
pub fn check(
    file: Option<&Path>,
    command: Option<&str>,
    cfg: &GovernanceConfig,
) -> Result<(), String> {
    if let Some(path) = file {
        if path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::Prefix(_)
                )
            })
        {
            return Err("DENY: absolute paths and parent traversal are forbidden".into());
        }
        if !cfg
            .allowed_paths
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            return Err("DENY: path outside allowed prefixes".into());
        }
    }
    if let Some(cmd) = command {
        let normalized = cmd.to_ascii_lowercase();
        if cfg
            .blocked_commands
            .iter()
            .any(|blocked| normalized.contains(&blocked.to_ascii_lowercase()))
        {
            return Err("DENY: blocked command pattern".into());
        }
    }
    Ok(())
}
