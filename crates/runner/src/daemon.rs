use crate::executor::execute_leased_task;
use crate::lock::WorkspaceLock;
use creatingj_api_client::{ApiError, RunnerClient};
use creatingj_audit::AuditTrail;
use creatingj_core::AgentConfig;
use creatingj_tools::ToolContext;
use creatingj_workspace::Workspace;
use std::path::Path;
use std::time::Duration;
use tracing::{error, info, warn};

pub async fn run_daemon(
    client: &RunnerClient,
    device_token: &str,
    config: &AgentConfig,
    workspace_path: &Path,
    once: bool,
) -> Result<(), ApiError> {
    let workspace = Workspace::detect(workspace_path)?;
    let _lock = WorkspaceLock::acquire(workspace.root())?;
    let audit = AuditTrail::default_path().ok().map(AuditTrail::new);
    let ctx = ToolContext::new(workspace, config.clone(), audit);

    info!(
        workspace = %ctx.workspace.root().display(),
        "creatingj-runner iniciado"
    );

    if once {
        let _ = client.heartbeat(device_token).await?;
        let lease = client.lease_task(device_token).await?;
        if lease.assigned
            && let Some(task) = lease.task
        {
            execute_leased_task(client, device_token, &ctx, &task).await?;
        }
        return Ok(());
    }

    let mut hb_interval =
        tokio::time::interval(Duration::from_secs(config.runner.heartbeat_interval_secs));
    let mut poll_interval =
        tokio::time::interval(Duration::from_secs(config.runner.lease_poll_interval_secs));
    let mut backoff_secs = 1u64;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("sinal de parada recebido; encerrando creatingj-runner");
                return Ok(());
            }
            _ = hb_interval.tick() => {
                match client.heartbeat(device_token).await {
                    Ok(dev) => {
                        backoff_secs = 1;
                        info!(device_id = %dev.id, online = dev.online, "heartbeat confirmado");
                    }
                    Err(err @ (ApiError::Unauthorized(_) | ApiError::Forbidden(_))) => {
                        error!("credencial do dispositivo revogada ou invalida; encerrando runner");
                        return Err(err);
                    }
                    Err(err) => {
                        warn!(backoff_secs, error = %err, "falha no heartbeat; aplicando backoff");
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(config.runner.max_backoff_secs);
                    }
                }
            }
            _ = poll_interval.tick() => {
                match client.lease_task(device_token).await {
                    Ok(lease) => {
                        backoff_secs = 1;
                        if lease.assigned
                            && let Some(task) = lease.task
                        {
                            info!(task_id = %task.id, title = %task.title, "tarefa recebida por lease");
                            if let Err(err) = execute_leased_task(client, device_token, &ctx, &task).await {
                                error!(task_id = %task.id, error = %err, "erro ao executar tarefa");
                            }
                        }
                    }
                    Err(err @ (ApiError::Unauthorized(_) | ApiError::Forbidden(_))) => {
                        error!("dispositivo desautorizado durante lease; encerrando runner");
                        return Err(err);
                    }
                    Err(err) => {
                        warn!(backoff_secs, error = %err, "falha ao consultar lease; aplicando backoff");
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(config.runner.max_backoff_secs);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn daemon_once_executes_leased_workspace_info_task_and_completes() {
        let server = MockServer::start().await;
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n",
        )
        .expect("write");

        let cfg = AgentConfig {
            api_base_url: server.uri(),
            ..AgentConfig::default()
        };
        let client = RunnerClient::from_config(&cfg).expect("client");

        Mock::given(method("POST"))
            .and(path("/api/v1/runner/heartbeat"))
            .and(header("X-Device-Token", "dev-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "dev-1",
                "name": "my-pc",
                "platform": "windows",
                "status": "ACTIVE",
                "online": true,
                "lastHeartbeatAt": "2026-11-22T23:00:00Z",
                "createdAt": "2026-11-22T22:00:00Z",
                "revokedAt": null
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/runner/tasks/lease"))
            .and(header("X-Device-Token", "dev-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "assigned": true,
                "task": {
                    "id": "task-1",
                    "projectId": "proj-1",
                    "deviceId": "dev-1",
                    "title": "Inspect workspace",
                    "instruction": "workspace.info",
                    "status": "RUNNING",
                    "leaseExpiresAt": "2026-11-22T23:05:00Z",
                    "resultSummary": null,
                    "errorCode": null,
                    "createdAt": "2026-11-22T23:00:00Z",
                    "updatedAt": "2026-11-22T23:00:00Z",
                    "completedAt": null
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/runner/tasks/task-1/events"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "event": {
                    "id": "ev-1",
                    "eventKey": "k1",
                    "eventType": "PROGRESS",
                    "message": "ok",
                    "createdAt": "2026-11-22T23:00:01Z"
                },
                "deduplicated": false
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/runner/tasks/task-1/complete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "task-1",
                "projectId": "proj-1",
                "deviceId": "dev-1",
                "title": "Inspect workspace",
                "instruction": "workspace.info",
                "status": "COMPLETED",
                "leaseExpiresAt": null,
                "resultSummary": "ok",
                "errorCode": null,
                "createdAt": "2026-11-22T23:00:00Z",
                "updatedAt": "2026-11-22T23:00:02Z",
                "completedAt": "2026-11-22T23:00:02Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        run_daemon(&client, "dev-secret", &cfg, dir.path(), true)
            .await
            .expect("daemon once");
    }

    #[tokio::test]
    async fn daemon_stops_immediately_when_device_is_revoked() {
        let server = MockServer::start().await;
        let dir = tempdir().expect("tempdir");
        let cfg = AgentConfig {
            api_base_url: server.uri(),
            ..AgentConfig::default()
        };
        let client = RunnerClient::from_config(&cfg).expect("client");

        Mock::given(method("POST"))
            .and(path("/api/v1/runner/heartbeat"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "status": 401,
                "detail": "Dispositivo revogado",
                "errorCode": "DEVICE_REVOKED"
            })))
            .mount(&server)
            .await;

        let err = run_daemon(&client, "revoked-tok", &cfg, dir.path(), true)
            .await
            .expect_err("must stop on 401");
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }
}
