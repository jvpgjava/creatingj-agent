use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    WorkspaceInfo,
    FilesList,
    FilesRead,
    CodeSearch,
    PatchPropose,
    PatchApply,
    TestsRun,
    CommandRun,
}

impl ToolKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceInfo => "workspace.info",
            Self::FilesList => "files.list",
            Self::FilesRead => "files.read",
            Self::CodeSearch => "code.search",
            Self::PatchPropose => "patch.propose",
            Self::PatchApply => "patch.apply",
            Self::TestsRun => "tests.run",
            Self::CommandRun => "command.run",
        }
    }

    pub const fn default_risk(self) -> RiskLevel {
        match self {
            Self::WorkspaceInfo | Self::FilesList | Self::FilesRead | Self::CodeSearch => {
                RiskLevel::Low
            }
            Self::PatchPropose | Self::TestsRun => RiskLevel::Medium,
            Self::PatchApply | Self::CommandRun => RiskLevel::High,
        }
    }

    pub const fn requires_explicit_approval(self) -> bool {
        matches!(self, Self::PatchApply | Self::CommandRun)
    }
}

impl fmt::Display for ToolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn risk_ordering_and_approval_requirements() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
        assert!(!ToolKind::FilesRead.requires_explicit_approval());
        assert!(ToolKind::PatchApply.requires_explicit_approval());
        assert!(ToolKind::CommandRun.requires_explicit_approval());
    }
}
