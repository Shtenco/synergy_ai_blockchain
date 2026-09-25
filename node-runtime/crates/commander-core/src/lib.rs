#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadFile,
    WriteFile,
    ListDirectory,
    RunCommand,
    InspectProcess,
    KillProcess,
    SystemInfo,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolPolicy {
    pub workspace_root: PathBuf,
    pub capabilities: Vec<Capability>,
    pub allowed_commands: Vec<String>,
    pub max_write_bytes: usize,
}

impl ToolPolicy {
    pub fn developer_default(workspace_root: PathBuf) -> Self {
        Self {
            workspace_root,
            capabilities: vec![
                Capability::ReadFile,
                Capability::WriteFile,
                Capability::ListDirectory,
                Capability::RunCommand,
                Capability::InspectProcess,
                Capability::KillProcess,
                Capability::SystemInfo,
            ],
            allowed_commands: vec![
                "cargo".into(),
                "rustc".into(),
                "git".into(),
                "python".into(),
                "python3".into(),
            ],
            max_write_bytes: 1024 * 1024,
        }
    }

    pub fn allows(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn resolve_workspace_path(&self, relative: &str) -> Result<PathBuf, PolicyError> {
        if relative.is_empty() {
            return Ok(self.workspace_root.clone());
        }
        let candidate = Path::new(relative);
        if candidate.is_absolute() {
            return Err(PolicyError::AbsolutePathDenied);
        }
        for c in candidate.components() {
            match c {
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(PolicyError::PathTraversalDenied)
                }
                _ => {}
            }
        }
        Ok(self.workspace_root.join(candidate))
    }

    pub fn validate_command(&self, program: &str) -> Result<(), PolicyError> {
        let base = Path::new(program)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(PolicyError::CommandDenied)?;
        if self
            .allowed_commands
            .iter()
            .any(|p| p.eq_ignore_ascii_case(base))
        {
            Ok(())
        } else {
            Err(PolicyError::CommandDenied)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    AbsolutePathDenied,
    PathTraversalDenied,
    CommandDenied,
    CapabilityDenied,
    WriteTooLarge,
}

pub fn ensure_capability(policy: &ToolPolicy, cap: Capability) -> Result<(), PolicyError> {
    if policy.allows(cap) {
        Ok(())
    } else {
        Err(PolicyError::CapabilityDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> ToolPolicy {
        ToolPolicy::developer_default(PathBuf::from("workspace"))
    }

    #[test]
    fn workspace_paths_fail_closed_on_escape() {
        assert_eq!(
            p().resolve_workspace_path("../secret"),
            Err(PolicyError::PathTraversalDenied)
        );
        assert!(p().resolve_workspace_path("src/lib.rs").is_ok());
    }

    #[test]
    fn command_allowlist_is_exact_on_program_basename() {
        assert!(p().validate_command("cargo").is_ok());
        assert!(p().validate_command("powershell.exe").is_err());
    }
}
