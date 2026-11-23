use creatingj_api_client::{ApiError, RunnerClient};
use creatingj_core::ToolKind;
use creatingj_permissions::{PolicyDecision, ToolRequest};
use creatingj_protocol::{
    RemoteTaskSummaryResponse, RunnerApprovalRequest, RunnerCompleteTaskRequest,
    RunnerTaskEventRequest,
};
use creatingj_tools::ToolContext;

#[allow(clippy::too_many_lines)]
pub async fn execute_leased_task(
    client: &RunnerClient,
    device_token: &str,
    ctx: &ToolContext,
    task: &RemoteTaskSummaryResponse,
) -> Result<(), ApiError> {
    emit_event(
        client,
        device_token,
        &task.id,
        1,
        &format!("Runner iniciou tarefa '{}'", task.title),
    )
    .await?;

    let instruction = task.instruction.trim();
    let lower = instruction.to_ascii_lowercase();

    if lower == "workspace.info" || lower.starts_with("info") {
        let info = ctx.workspace_info()?;
        let summary = format!(
            "Workspace {} | git={} | stacks=[{}] | arquivos={}",
            info.root,
            info.is_git_repo,
            info.detected_stacks.join(", "),
            info.file_count
        );
        emit_event(client, device_token, &task.id, 2, &summary).await?;
        complete_ok(client, device_token, &task.id, &summary).await?;
        return Ok(());
    }

    if lower == "files.list" || lower.starts_with("list ") {
        let files = ctx.list_files(200)?;
        let summary = format!("{} arquivos listados no workspace.", files.len());
        emit_event(client, device_token, &task.id, 2, &summary).await?;
        complete_ok(client, device_token, &task.id, &summary).await?;
        return Ok(());
    }

    if let Some(path) = strip_prefix_ci(instruction, "files.read ") {
        match ctx.read_file(path.trim()) {
            Ok(snap) => {
                let summary = format!(
                    "Arquivo {} lido ({} bytes, sha256={}).",
                    snap.relative_path,
                    snap.bytes,
                    &snap.sha256[..12]
                );
                emit_event(client, device_token, &task.id, 2, &summary).await?;
                complete_ok(client, device_token, &task.id, &summary).await?;
            }
            Err(err) => {
                let msg = format!("Leitura negada/falhou: {err}");
                emit_event(client, device_token, &task.id, 2, &msg).await?;
                complete_err(client, device_token, &task.id, &msg, "POLICY_DENIED").await?;
            }
        }
        return Ok(());
    }

    if let Some(query) = strip_prefix_ci(instruction, "code.search ") {
        let matches = ctx.search(query.trim(), Some(50))?;
        let summary = format!("Busca retornou {} ocorrencias.", matches.len());
        emit_event(client, device_token, &task.id, 2, &summary).await?;
        complete_ok(client, device_token, &task.id, &summary).await?;
        return Ok(());
    }

    if let Some(cmd) = strip_prefix_ci(instruction, "tests.run ") {
        let cmd = cmd.trim();
        let decision = ctx.permissions.evaluate(&ToolRequest {
            tool: ToolKind::TestsRun,
            target_path: None,
            command_text: Some(cmd.to_owned()),
            diff_preview: None,
        });
        match decision {
            PolicyDecision::Allow { .. } => {
                emit_event(
                    client,
                    device_token,
                    &task.id,
                    2,
                    &format!("Executando testes autorizados: {cmd}"),
                )
                .await?;
                let out = ctx.run_tests(cmd, None).await?;
                if out.exit_code == 0 && !out.timed_out {
                    let summary = format!("Testes aprovados (exit=0): {cmd}");
                    emit_event(client, device_token, &task.id, 3, &summary).await?;
                    complete_ok(client, device_token, &task.id, &summary).await?;
                } else {
                    let summary = format!(
                        "Testes falharam (exit={}, timed_out={}): {cmd}",
                        out.exit_code, out.timed_out
                    );
                    emit_event(client, device_token, &task.id, 3, &summary).await?;
                    complete_err(client, device_token, &task.id, &summary, "TESTS_FAILED").await?;
                }
            }
            PolicyDecision::RequireApproval { reason, .. } => {
                let _ = client
                    .request_approval(
                        device_token,
                        &task.id,
                        &RunnerApprovalRequest {
                            tool_name: "RUN_COMMAND".to_owned(),
                            target_path: None,
                            command_text: Some(cmd.to_owned()),
                            diff_preview: None,
                            ttl_seconds: Some(300),
                        },
                    )
                    .await?;
                emit_event(
                    client,
                    device_token,
                    &task.id,
                    2,
                    &format!("Aguardando aprovacao remota: {reason}"),
                )
                .await?;
            }
            PolicyDecision::Deny { reason } => {
                emit_event(
                    client,
                    device_token,
                    &task.id,
                    2,
                    &format!("Bloqueado por politica: {reason}"),
                )
                .await?;
                complete_err(client, device_token, &task.id, &reason, "POLICY_DENIED").await?;
            }
        }
        return Ok(());
    }

    if let Some(cmd) = strip_prefix_ci(instruction, "command.run ") {
        let cmd = cmd.trim();
        let decision = ctx.permissions.evaluate(&ToolRequest {
            tool: ToolKind::CommandRun,
            target_path: None,
            command_text: Some(cmd.to_owned()),
            diff_preview: None,
        });
        match decision {
            PolicyDecision::Deny { reason } => {
                emit_event(
                    client,
                    device_token,
                    &task.id,
                    2,
                    &format!("Comando bloqueado: {reason}"),
                )
                .await?;
                complete_err(client, device_token, &task.id, &reason, "POLICY_DENIED").await?;
            }
            PolicyDecision::RequireApproval { reason, .. } => {
                let _ = client
                    .request_approval(
                        device_token,
                        &task.id,
                        &RunnerApprovalRequest {
                            tool_name: "RUN_COMMAND".to_owned(),
                            target_path: None,
                            command_text: Some(cmd.to_owned()),
                            diff_preview: None,
                            ttl_seconds: Some(300),
                        },
                    )
                    .await?;
                emit_event(
                    client,
                    device_token,
                    &task.id,
                    2,
                    &format!("Aprovacao remota solicitada para comando: {reason}"),
                )
                .await?;
            }
            PolicyDecision::Allow { .. } => {
                let _ = client
                    .request_approval(
                        device_token,
                        &task.id,
                        &RunnerApprovalRequest {
                            tool_name: "RUN_COMMAND".to_owned(),
                            target_path: None,
                            command_text: Some(cmd.to_owned()),
                            diff_preview: None,
                            ttl_seconds: Some(300),
                        },
                    )
                    .await?;
                emit_event(
                    client,
                    device_token,
                    &task.id,
                    2,
                    "Aprovacao remota solicitada para execucao de comando",
                )
                .await?;
            }
        }
        return Ok(());
    }

    let info = ctx.workspace_info()?;
    let summary = format!(
        "Tarefa analisada no workspace {} ({} arquivos). Nenhuma acao destrutiva executada sem aprovacao.",
        info.root, info.file_count
    );
    emit_event(client, device_token, &task.id, 2, &summary).await?;
    complete_ok(client, device_token, &task.id, &summary).await?;
    Ok(())
}

async fn emit_event(
    client: &RunnerClient,
    device_token: &str,
    task_id: &str,
    seq: u32,
    message: &str,
) -> Result<(), ApiError> {
    let _ = client
        .post_event(
            device_token,
            task_id,
            &RunnerTaskEventRequest {
                event_key: format!("task-{task_id}-seq-{seq}"),
                message: message.to_owned(),
            },
        )
        .await?;
    Ok(())
}

async fn complete_ok(
    client: &RunnerClient,
    device_token: &str,
    task_id: &str,
    summary: &str,
) -> Result<(), ApiError> {
    let _ = client
        .complete_task(
            device_token,
            task_id,
            &RunnerCompleteTaskRequest {
                succeeded: true,
                result_summary: Some(summary.to_owned()),
                error_code: None,
            },
        )
        .await?;
    Ok(())
}

async fn complete_err(
    client: &RunnerClient,
    device_token: &str,
    task_id: &str,
    summary: &str,
    error_code: &str,
) -> Result<(), ApiError> {
    let _ = client
        .complete_task(
            device_token,
            task_id,
            &RunnerCompleteTaskRequest {
                succeeded: false,
                result_summary: Some(summary.to_owned()),
                error_code: Some(error_code.to_owned()),
            },
        )
        .await?;
    Ok(())
}

fn strip_prefix_ci<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    if input.len() >= prefix.len() && input[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&input[prefix.len()..])
    } else {
        None
    }
}
