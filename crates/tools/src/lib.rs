pub mod command;
pub mod patch;
pub mod search;

use creatingj_audit::{AuditEvent, AuditTrail};
use creatingj_core::{AgentConfig, CoreError, ToolKind};
use creatingj_permissions::{ApprovalGrant, PermissionEngine, PolicyDecision, ToolRequest};
use creatingj_workspace::{FileSnapshot, Workspace, WorkspaceInfo};

pub use command::{CommandOutput, run_command_authorized, run_tests};
pub use patch::{PatchApplyResult, PatchProposal, apply_patch, propose_patch};
pub use search::{SearchMatch, search_code};

#[derive(Debug, Clone)]
pub struct ToolContext {
    pub workspace: Workspace,
    pub config: AgentConfig,
    pub permissions: PermissionEngine,
    pub audit: Option<AuditTrail>,
}

impl ToolContext {
    pub fn new(workspace: Workspace, config: AgentConfig, audit: Option<AuditTrail>) -> Self {
        Self {
            workspace,
            config,
            permissions: PermissionEngine,
            audit,
        }
    }

    pub fn workspace_info(&self) -> Result<WorkspaceInfo, CoreError> {
        let info = self.workspace.info()?;
        self.record_audit(
            "tool.workspace.info",
            "ok",
            Some(ToolKind::WorkspaceInfo),
            Some(info.root.clone()),
            format!("files={}", info.file_count),
        );
        Ok(info)
    }

    pub fn list_files(&self, max_entries: usize) -> Result<Vec<String>, CoreError> {
        let files = self.workspace.list_files(max_entries)?;
        self.record_audit(
            "tool.files.list",
            "ok",
            Some(ToolKind::FilesList),
            None,
            format!("count={}", files.len()),
        );
        Ok(files)
    }

    pub fn read_file(&self, relative_path: &str) -> Result<FileSnapshot, CoreError> {
        let decision = self.permissions.evaluate(&ToolRequest {
            tool: ToolKind::FilesRead,
            target_path: Some(relative_path.to_owned()),
            command_text: None,
            diff_preview: None,
        });
        if let PolicyDecision::Deny { reason } = decision {
            self.record_audit(
                "tool.files.read",
                "denied",
                Some(ToolKind::FilesRead),
                Some(relative_path.to_owned()),
                &reason,
            );
            return Err(CoreError::PermissionDenied(reason));
        }
        let snapshot = self
            .workspace
            .read_file_snapshot(relative_path, self.config.max_file_bytes)?;
        self.record_audit(
            "tool.files.read",
            "ok",
            Some(ToolKind::FilesRead),
            Some(snapshot.relative_path.clone()),
            format!("bytes={}", snapshot.bytes),
        );
        Ok(snapshot)
    }

    pub fn search(
        &self,
        query: &str,
        max_results: Option<usize>,
    ) -> Result<Vec<SearchMatch>, CoreError> {
        let limit = max_results.unwrap_or(self.config.max_search_results);
        let matches = search_code(&self.workspace, query, limit, self.config.max_file_bytes)?;
        self.record_audit(
            "tool.code.search",
            "ok",
            Some(ToolKind::CodeSearch),
            None,
            format!("matches={}", matches.len()),
        );
        Ok(matches)
    }

    pub fn propose_patch(
        &self,
        relative_path: &str,
        new_content: &str,
    ) -> Result<PatchProposal, CoreError> {
        propose_patch(self, relative_path, new_content)
    }

    pub fn apply_patch(
        &self,
        proposal: &PatchProposal,
        grant: &ApprovalGrant,
    ) -> Result<PatchApplyResult, CoreError> {
        apply_patch(self, proposal, grant)
    }

    pub async fn run_tests(
        &self,
        command_text: &str,
        grant: Option<&ApprovalGrant>,
    ) -> Result<CommandOutput, CoreError> {
        run_tests(self, command_text, grant).await
    }

    pub async fn run_command(
        &self,
        command_text: &str,
        grant: &ApprovalGrant,
    ) -> Result<CommandOutput, CoreError> {
        run_command_authorized(self, command_text, grant).await
    }

    pub(crate) fn record_audit(
        &self,
        action: &str,
        outcome: &str,
        tool: Option<ToolKind>,
        target: Option<String>,
        detail: impl AsRef<str>,
    ) {
        if let Some(trail) = &self.audit {
            let event = AuditEvent::new(
                action,
                outcome,
                tool.map(|t| t.as_str().to_owned()),
                target,
                detail,
            );
            let _ = trail.record(&event);
        }
    }
}
