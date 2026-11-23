use chrono::{DateTime, Duration, Utc};
use creatingj_core::{CoreError, ToolKind, sha256_hex};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalGrant {
    pub approval_id: String,
    pub task_id: Option<String>,
    pub approval_hash: String,
    pub approved_by: String,
    pub expires_at: DateTime<Utc>,
}

impl ApprovalGrant {
    pub fn issue(
        approval_id: impl Into<String>,
        task_id: Option<String>,
        approval_hash: impl Into<String>,
        approved_by: impl Into<String>,
        ttl_secs: i64,
    ) -> Self {
        Self {
            approval_id: approval_id.into(),
            task_id,
            approval_hash: approval_hash.into(),
            approved_by: approved_by.into(),
            expires_at: Utc::now() + Duration::seconds(ttl_secs.max(1)),
        }
    }

    pub fn verify(&self, expected_hash: &str, now: DateTime<Utc>) -> Result<(), CoreError> {
        if now > self.expires_at {
            return Err(CoreError::PermissionDenied(
                "aprovacao expirada; solicite nova aprovacao".to_owned(),
            ));
        }
        if self.approval_hash != expected_hash {
            return Err(CoreError::PermissionDenied(
                "argumentos ou diff alterados apos aprovacao; nova aprovacao obrigatoria"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn compute_approval_hash(
    tool: ToolKind,
    target_path: Option<&str>,
    command_text: Option<&str>,
    diff_preview: Option<&str>,
) -> String {
    let payload = format!(
        "tool={}\npath={}\ncmd={}\ndiff={}",
        tool.as_str(),
        target_path.unwrap_or(""),
        command_text.unwrap_or(""),
        diff_preview.unwrap_or("")
    );
    sha256_hex(payload.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_rejects_expired_and_tampered_hashes() {
        let hash = compute_approval_hash(
            ToolKind::PatchApply,
            Some("src/main.rs"),
            None,
            Some("+println!(\"ok\");"),
        );
        let grant = ApprovalGrant::issue("apr-1", None, &hash, "user-1", 60);
        assert!(grant.verify(&hash, Utc::now()).is_ok());

        let tampered = compute_approval_hash(
            ToolKind::PatchApply,
            Some("src/main.rs"),
            None,
            Some("+println!(\"tampered\");"),
        );
        assert!(grant.verify(&tampered, Utc::now()).is_err());

        let expired_time = Utc::now() + Duration::seconds(120);
        assert!(grant.verify(&hash, expired_time).is_err());
    }
}
