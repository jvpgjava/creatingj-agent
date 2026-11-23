use crate::ToolContext;
use chrono::Utc;
use creatingj_core::{CoreError, ToolKind, sha256_hex};
use creatingj_permissions::{ApprovalGrant, PolicyDecision, ToolRequest, compute_approval_hash};
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchProposal {
    pub relative_path: String,
    pub existed: bool,
    pub base_sha256: Option<String>,
    pub new_sha256: String,
    pub new_content: String,
    pub unified_diff: String,
    pub approval_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchApplyResult {
    pub relative_path: String,
    pub applied: bool,
    pub new_sha256: String,
}

pub fn propose_patch(
    ctx: &ToolContext,
    relative_path: &str,
    new_content: &str,
) -> Result<PatchProposal, CoreError> {
    if new_content.len() > ctx.config.max_file_bytes {
        return Err(CoreError::Validation(format!(
            "conteudo proposto excede limite de {} bytes",
            ctx.config.max_file_bytes
        )));
    }
    let canonical = ctx.workspace.resolve_safe_path(relative_path)?;
    let rel = ctx.workspace.relative_display(&canonical)?;

    let (existed, old_content, base_sha256) = if canonical.exists() {
        let snap = ctx
            .workspace
            .read_file_snapshot(&rel, ctx.config.max_file_bytes)?;
        (true, snap.content, Some(snap.sha256))
    } else {
        (false, String::new(), None)
    };

    let diff = TextDiff::from_lines(old_content.as_str(), new_content)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{rel}"), &format!("b/{rel}"))
        .to_string();

    let decision = ctx.permissions.evaluate(&ToolRequest {
        tool: ToolKind::PatchPropose,
        target_path: Some(rel.clone()),
        command_text: None,
        diff_preview: Some(diff.clone()),
    });
    if let PolicyDecision::Deny { reason } = decision {
        ctx.record_audit(
            "tool.patch.propose",
            "denied",
            Some(ToolKind::PatchPropose),
            Some(rel),
            &reason,
        );
        return Err(CoreError::PermissionDenied(reason));
    }

    let approval_hash = compute_approval_hash(ToolKind::PatchApply, Some(&rel), None, Some(&diff));
    let new_sha256 = sha256_hex(new_content.as_bytes());

    ctx.record_audit(
        "tool.patch.propose",
        "ok",
        Some(ToolKind::PatchPropose),
        Some(rel.clone()),
        format!("existed={existed} diff_bytes={}", diff.len()),
    );

    Ok(PatchProposal {
        relative_path: rel,
        existed,
        base_sha256,
        new_sha256,
        new_content: new_content.to_owned(),
        unified_diff: diff,
        approval_hash,
    })
}

pub fn apply_patch(
    ctx: &ToolContext,
    proposal: &PatchProposal,
    grant: &ApprovalGrant,
) -> Result<PatchApplyResult, CoreError> {
    let canonical = ctx.workspace.resolve_safe_path(&proposal.relative_path)?;
    let rel = ctx.workspace.relative_display(&canonical)?;

    let decision = ctx.permissions.evaluate(&ToolRequest {
        tool: ToolKind::PatchApply,
        target_path: Some(rel.clone()),
        command_text: None,
        diff_preview: Some(proposal.unified_diff.clone()),
    });

    let expected_hash = match decision {
        PolicyDecision::Deny { reason } => {
            ctx.record_audit(
                "tool.patch.apply",
                "denied",
                Some(ToolKind::PatchApply),
                Some(rel),
                &reason,
            );
            return Err(CoreError::PermissionDenied(reason));
        }
        PolicyDecision::RequireApproval { approval_hash, .. } => approval_hash,
        PolicyDecision::Allow { .. } => proposal.approval_hash.clone(),
    };

    grant.verify(&expected_hash, Utc::now())?;

    let backup = if canonical.exists() {
        let current_bytes = fs::read(&canonical)?;
        let current_hash = sha256_hex(&current_bytes);
        if proposal.base_sha256.as_deref() != Some(current_hash.as_str()) {
            ctx.record_audit(
                "tool.patch.apply",
                "conflict",
                Some(ToolKind::PatchApply),
                Some(rel.clone()),
                "hash base divergente de arquivo atual em disco",
            );
            return Err(CoreError::Conflict(format!(
                "conflito de edicao em {rel}: o arquivo foi modificado apos a proposta do patch"
            )));
        }
        Some(current_bytes)
    } else {
        if proposal.existed {
            return Err(CoreError::Conflict(format!(
                "arquivo {rel} foi removido apos a proposta do patch"
            )));
        }
        None
    };

    if let Some(parent) = canonical.parent() {
        fs::create_dir_all(parent)?;
    }

    if let Err(err) = fs::write(&canonical, proposal.new_content.as_bytes()) {
        if let Some(orig) = backup {
            let _ = fs::write(&canonical, orig);
        }
        return Err(CoreError::Io(err));
    }

    let written_hash = sha256_hex(proposal.new_content.as_bytes());
    ctx.record_audit(
        "tool.patch.apply",
        "ok",
        Some(ToolKind::PatchApply),
        Some(rel.clone()),
        format!(
            "approval_id={} new_sha256={written_hash}",
            grant.approval_id
        ),
    );

    Ok(PatchApplyResult {
        relative_path: rel,
        applied: true,
        new_sha256: written_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use creatingj_core::AgentConfig;
    use creatingj_workspace::Workspace;
    use tempfile::tempdir;

    #[test]
    fn patch_apply_requires_valid_approval_and_detects_external_edit_conflict() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("app.rs"), "fn main() {}\n").expect("write");
        let ws = Workspace::open(dir.path()).expect("ws");
        let ctx = ToolContext::new(ws, AgentConfig::default(), None);

        let proposal = ctx
            .propose_patch("app.rs", "fn main() {\n    println!(\"ok\");\n}\n")
            .expect("propose");
        assert!(proposal.unified_diff.contains("println!(\"ok\")"));

        let bad_grant = ApprovalGrant::issue("a1", None, "wrong-hash", "user", 60);
        assert!(ctx.apply_patch(&proposal, &bad_grant).is_err());

        fs::write(
            dir.path().join("app.rs"),
            "fn main() { /* human edit */ }\n",
        )
        .expect("edit");
        let valid_grant = ApprovalGrant::issue("a2", None, &proposal.approval_hash, "user", 60);
        let conflict = ctx.apply_patch(&proposal, &valid_grant);
        assert!(matches!(conflict, Err(CoreError::Conflict(_))));
    }

    #[test]
    fn patch_apply_writes_cleanly_with_valid_grant() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("lib.rs"), "pub fn a() -> i32 { 1 }\n").expect("write");
        let ws = Workspace::open(dir.path()).expect("ws");
        let ctx = ToolContext::new(ws, AgentConfig::default(), None);

        let proposal = ctx
            .propose_patch("lib.rs", "pub fn a() -> i32 { 2 }\n")
            .expect("propose");
        let grant = ApprovalGrant::issue("a3", None, &proposal.approval_hash, "user", 60);
        let res = ctx.apply_patch(&proposal, &grant).expect("apply");
        assert!(res.applied);
        let updated = fs::read_to_string(dir.path().join("lib.rs")).expect("read");
        assert_eq!(updated, "pub fn a() -> i32 { 2 }\n");
    }
}
