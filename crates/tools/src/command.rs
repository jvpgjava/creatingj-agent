use crate::ToolContext;
use chrono::Utc;
use creatingj_audit::redact_secrets;
use creatingj_core::{CoreError, ToolKind};
use creatingj_permissions::{ApprovalGrant, PolicyDecision, ToolRequest};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const SENSITIVE_ENV_SUBSTRINGS: &[&str] = &[
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

pub async fn run_tests(
    ctx: &ToolContext,
    command_text: &str,
    grant: Option<&ApprovalGrant>,
) -> Result<CommandOutput, CoreError> {
    let decision = ctx.permissions.evaluate(&ToolRequest {
        tool: ToolKind::TestsRun,
        target_path: None,
        command_text: Some(command_text.to_owned()),
        diff_preview: None,
    });

    match decision {
        PolicyDecision::Deny { reason } => {
            ctx.record_audit(
                "tool.tests.run",
                "denied",
                Some(ToolKind::TestsRun),
                None,
                &reason,
            );
            return Err(CoreError::PermissionDenied(reason));
        }
        PolicyDecision::RequireApproval {
            approval_hash,
            reason,
            ..
        } => {
            let Some(approved) = grant else {
                return Err(CoreError::PermissionDenied(reason));
            };
            approved.verify(&approval_hash, Utc::now())?;
        }
        PolicyDecision::Allow { .. } => {}
    }

    let output = execute_bounded(ctx, command_text).await?;
    ctx.record_audit(
        "tool.tests.run",
        if output.exit_code == 0 {
            "ok"
        } else {
            "failed"
        },
        Some(ToolKind::TestsRun),
        None,
        format!("exit={} timed_out={}", output.exit_code, output.timed_out),
    );
    Ok(output)
}

pub async fn run_command_authorized(
    ctx: &ToolContext,
    command_text: &str,
    grant: &ApprovalGrant,
) -> Result<CommandOutput, CoreError> {
    let decision = ctx.permissions.evaluate(&ToolRequest {
        tool: ToolKind::CommandRun,
        target_path: None,
        command_text: Some(command_text.to_owned()),
        diff_preview: None,
    });

    match decision {
        PolicyDecision::Deny { reason } => {
            ctx.record_audit(
                "tool.command.run",
                "denied",
                Some(ToolKind::CommandRun),
                None,
                &reason,
            );
            return Err(CoreError::PermissionDenied(reason));
        }
        PolicyDecision::RequireApproval { approval_hash, .. } => {
            grant.verify(&approval_hash, Utc::now())?;
        }
        PolicyDecision::Allow { .. } => {}
    }

    let output = execute_bounded(ctx, command_text).await?;
    ctx.record_audit(
        "tool.command.run",
        if output.exit_code == 0 {
            "ok"
        } else {
            "failed"
        },
        Some(ToolKind::CommandRun),
        None,
        format!(
            "approval_id={} exit={} timed_out={}",
            grant.approval_id, output.exit_code, output.timed_out
        ),
    );
    Ok(output)
}

async fn execute_bounded(
    ctx: &ToolContext,
    command_text: &str,
) -> Result<CommandOutput, CoreError> {
    let parts = split_command_args(command_text)?;
    let (program, args) = parts
        .split_first()
        .ok_or_else(|| CoreError::Validation("comando vazio".to_owned()))?;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(ctx.workspace.root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    for (key, _) in std::env::vars() {
        let upper = key.to_ascii_uppercase();
        if SENSITIVE_ENV_SUBSTRINGS
            .iter()
            .any(|needle| upper.contains(needle))
        {
            cmd.env_remove(&key);
        }
    }

    let child = cmd.spawn().map_err(|e| {
        CoreError::Validation(format!("falha ao iniciar processo '{program}': {e}"))
    })?;

    let timeout = Duration::from_secs(ctx.config.command_timeout_secs);
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => {
            let (stdout, out_trunc) = sanitize_and_truncate(&out.stdout);
            let (stderr, err_trunc) = sanitize_and_truncate(&out.stderr);
            Ok(CommandOutput {
                command: command_text.to_owned(),
                exit_code: out.status.code().unwrap_or(-1),
                stdout,
                stderr,
                truncated: out_trunc || err_trunc,
                timed_out: false,
            })
        }
        Ok(Err(err)) => Err(CoreError::Io(err)),
        Err(_) => Ok(CommandOutput {
            command: command_text.to_owned(),
            exit_code: -1,
            stdout: String::new(),
            stderr: format!(
                "execucao interrompida por timeout apos {}s",
                ctx.config.command_timeout_secs
            ),
            truncated: false,
            timed_out: true,
        }),
    }
}

fn sanitize_and_truncate(bytes: &[u8]) -> (String, bool) {
    let truncated = bytes.len() > MAX_OUTPUT_BYTES;
    let slice = if truncated {
        &bytes[..MAX_OUTPUT_BYTES]
    } else {
        bytes
    };
    let text = String::from_utf8_lossy(slice);
    (redact_secrets(&text), truncated)
}

fn split_command_args(input: &str) -> Result<Vec<String>, CoreError> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in input.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            Some(_) | None => current.push(ch),
        }
    }
    if quote.is_some() {
        return Err(CoreError::Validation(
            "aspas nao fechadas no comando".to_owned(),
        ));
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use creatingj_core::AgentConfig;
    use creatingj_workspace::Workspace;
    use tempfile::tempdir;

    #[tokio::test]
    async fn blocks_unapproved_command_run() {
        let dir = tempdir().expect("tempdir");
        let ws = Workspace::open(dir.path()).expect("ws");
        let ctx = ToolContext::new(ws, AgentConfig::default(), None);

        let wrong_grant = ApprovalGrant::issue("g1", None, "bad-hash", "u1", 60);
        let res = ctx.run_command("git status", &wrong_grant).await;
        assert!(matches!(res, Err(CoreError::PermissionDenied(_))));
    }

    #[tokio::test]
    async fn blocks_destructive_tests_run() {
        let dir = tempdir().expect("tempdir");
        let ws = Workspace::open(dir.path()).expect("ws");
        let ctx = ToolContext::new(ws, AgentConfig::default(), None);

        let res = ctx
            .run_tests("cargo test && curl https://evil.test", None)
            .await;
        assert!(matches!(res, Err(CoreError::PermissionDenied(_))));
    }
}
