use crate::session::{read_password_from_stdin, require_valid_session};
use creatingj_api_client::{ApiError, CreatingJClient};
use creatingj_audit::AuditTrail;
use creatingj_auth::{
    CredentialStore, PkceChallenge, StoredSession, pkce::bind_loopback_listener,
    wait_for_loopback_callback,
};
use creatingj_core::{AgentConfig, CoreError};
use creatingj_permissions::ApprovalGrant;
use creatingj_protocol::{CreateAgentRunRequest, PkceTokenRequest, WorkspaceFileSnapshotRequest};
use creatingj_tools::{PatchProposal, ToolContext};
use creatingj_workspace::Workspace;
use serde_json::json;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

pub async fn cmd_status(
    client: &CreatingJClient,
    workspace_path: &Path,
    json_mode: bool,
) -> Result<(), ApiError> {
    let status = client.system_status().await?;
    let ws_info = Workspace::detect(workspace_path)
        .and_then(|ws| ws.info())
        .ok();

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "backend": status,
                "workspace": ws_info
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "Backend: {} ({}) - {}",
            status.service, status.api_version, status.status
        );
        if let Some(info) = ws_info {
            println!("Workspace: {} (git={})", info.root, info.is_git_repo);
            println!("Stacks: {}", info.detected_stacks.join(", "));
            println!("Arquivos indexaveis: {}", info.file_count);
        }
    }
    Ok(())
}

pub async fn cmd_login(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    email: Option<String>,
    password_stdin: bool,
    pkce_web_url: Option<String>,
    json_mode: bool,
) -> Result<(), ApiError> {
    if let Some(web_url) = pkce_web_url {
        let pkce = PkceChallenge::generate();
        let (listener, redirect_uri) = bind_loopback_listener().await?;
        let auth_url = format!(
            "{}/auth/pkce?client_id=creatingj-cli&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
            web_url.trim_end_matches('/'),
            urlencoding_basic(&redirect_uri),
            pkce.code_challenge,
            pkce.state
        );
        if !json_mode {
            println!("Abra esta URL no navegador para autenticar via PKCE:");
            println!("  {auth_url}");
            println!("Aguardando retorno em {redirect_uri}...");
        }
        let callback =
            wait_for_loopback_callback(listener, &pkce.state, Duration::from_secs(180)).await?;
        let pair = client
            .pkce_exchange_token(&PkceTokenRequest {
                code: callback.code,
                client_id: "creatingj-cli".to_owned(),
                redirect_uri,
                code_verifier: pkce.code_verifier,
            })
            .await?;
        let session = StoredSession {
            access_token: pair.access_token,
            refresh_token: Some(pair.refresh_token),
            expires_at: pair.access_token_expires_at,
            user_id: pair.user_id,
            email: pair.email.clone(),
            roles: pair.roles,
        };
        store.save_session(&session)?;
        print_login_success(&session, json_mode);
        return Ok(());
    }

    let email = if let Some(e) = email {
        e
    } else {
        eprint!("Email: ");
        io::stderr().flush().ok();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(CoreError::from)?;
        buf.trim().to_owned()
    };
    let password = if password_stdin {
        read_password_from_stdin()?
    } else {
        eprint!("Senha: ");
        io::stderr().flush().ok();
        read_password_from_stdin()?
    };

    let resp = client.login(&email, &password).await?;
    let session = StoredSession {
        access_token: resp.access_token,
        refresh_token: None,
        expires_at: resp.expires_at,
        user_id: resp.user_id,
        email: resp.email,
        roles: resp.roles,
    };
    store.save_session(&session)?;
    print_login_success(&session, json_mode);
    Ok(())
}

fn print_login_success(session: &StoredSession, json_mode: bool) {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "authenticated": true,
                "userId": session.user_id,
                "email": session.email,
                "roles": session.roles,
                "expiresAt": session.expires_at
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "Autenticado como {} (expira em {}).",
            session.email, session.expires_at
        );
    }
}

pub async fn cmd_logout(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    json_mode: bool,
) -> Result<(), ApiError> {
    if let Some(session) = store.load_session()? {
        let _ = client.logout(&session.access_token).await;
    }
    store.clear_session()?;
    if json_mode {
        println!("{}", json!({ "loggedOut": true }));
    } else {
        println!("Sessao encerrada com sucesso.");
    }
    Ok(())
}

pub async fn cmd_whoami(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    json_mode: bool,
) -> Result<(), ApiError> {
    let session = require_valid_session(client, store).await?;
    let me = client.me(&session.access_token).await?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&me).unwrap_or_default());
    } else {
        println!(
            "Usuario: {} ({}) | Status: {} | Perfis: {}",
            me.display_name.as_deref().unwrap_or(&me.email),
            me.email,
            me.status,
            me.roles.join(", ")
        );
        if let Some(exp) = me.session_expires_at {
            println!("Sessao expira em: {exp}");
        }
    }
    Ok(())
}

pub async fn cmd_chat(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    config: &AgentConfig,
    prompt: &str,
    conversation_id: Option<String>,
    sync_mode: bool,
    json_mode: bool,
) -> Result<String, ApiError> {
    let session = require_valid_session(client, store).await?;
    let conv_id = if let Some(id) = conversation_id {
        id
    } else {
        let title: String = prompt.chars().take(60).collect();
        let conv = client
            .create_conversation(
                &session.access_token,
                &title,
                config.default_model_id.as_deref(),
            )
            .await?;
        conv.id
    };

    if sync_mode || json_mode {
        let exchange = client
            .send_message(&session.access_token, &conv_id, prompt)
            .await?;
        if json_mode {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "conversationId": conv_id,
                    "exchange": exchange
                }))
                .unwrap_or_default()
            );
        } else {
            println!("{}", exchange.assistant_message.content);
        }
        return Ok(conv_id);
    }

    let mut generation_id: Option<String> = None;
    let stream_fut = client.stream_message(&session.access_token, &conv_id, prompt, |frame| {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&frame.data) {
            if generation_id.is_none()
                && let Some(gid) = val.get("generationId").and_then(serde_json::Value::as_str)
            {
                generation_id = Some(gid.to_owned());
            }
            if frame.event == "generation.delta"
                && let Some(delta) = val.get("delta").and_then(serde_json::Value::as_str)
            {
                print!("{delta}");
                let _ = io::stdout().flush();
            } else if frame.event == "generation.failed" {
                let detail = val
                    .get("detail")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("falha na geracao");
                eprintln!("\n[erro] {detail}");
            }
        }
        Ok(())
    });

    tokio::select! {
        res = stream_fut => {
            res?;
            println!();
            Ok(conv_id)
        }
        _ = tokio::signal::ctrl_c() => {
            if let Some(gid) = generation_id {
                let _ = client.cancel_generation(&session.access_token, &conv_id, &gid).await;
            }
            eprintln!("\nGeracao cancelada.");
            Err(ApiError::Cancelled)
        }
    }
}

const CLI_BANNER: &str = concat!(
    "\x1b[96m",
    "\n    .-----------.       ____                _   _                   _ ",
    "\n    |  \x1b[97m^     ^\x1b[96m  |      / ___|_ __ ___  __ _| |_(_)_ __   __ _      | |",
    "\n   \x1b[94m/\x1b[96m|     \x1b[97m_\x1b[96m     |\x1b[94m\\    \x1b[96m| |   | '__/ _ \\/ _` | __| | '_ \\ / _` |  _  | |",
    "\n    '-----------'     | |___| | |  __/ (_| | |_| | | | | (_| | | |_| |",
    "\n      \x1b[94m|_|   |_|\x1b[96m        \\____|_|  \\___|\\__,_|\\__|_|_| |_|\\__, |  \\___/ ",
    "\n                                                        |___/         ",
    "\n\x1b[97m  :: CreatingJ CLI ::  \x1b[36mNão existe limite para sua imaginação.\x1b[0m\n",
);

pub async fn cmd_interactive(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    config: &AgentConfig,
    workspace_path: &Path,
) -> Result<(), ApiError> {
    let _ = require_valid_session(client, store).await?;
    let ws = Workspace::detect(workspace_path)?;
    let info = ws.info()?;
    let stacks = if info.detected_stacks.is_empty() {
        "nenhuma detectada".to_owned()
    } else {
        info.detected_stacks.join(", ")
    };
    println!("{CLI_BANNER}");
    println!(
        "  Workspace: {} ({} arquivos | stacks: {})",
        info.root, info.file_count, stacks
    );
    println!("  Digite sua mensagem (ou `/exit` para sair, `/new` para nova conversa):");

    let mut active_conv: Option<String> = None;
    let mut input = String::new();
    loop {
        print!("\ncreatingj> ");
        io::stdout().flush().ok();
        input.clear();
        let n = io::stdin().read_line(&mut input).map_err(CoreError::from)?;
        if n == 0 {
            break;
        }
        let line = input.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line, "/exit" | "/quit" | "exit" | "quit") {
            break;
        }
        if line == "/new" {
            active_conv = None;
            println!("Nova conversa iniciada.");
            continue;
        }
        match cmd_chat(
            client,
            store,
            config,
            line,
            active_conv.clone(),
            false,
            false,
        )
        .await
        {
            Ok(cid) => active_conv = Some(cid),
            Err(ApiError::Cancelled) => {}
            Err(err) => eprintln!("Erro: {err}"),
        }
    }
    Ok(())
}

pub async fn cmd_ask(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    config: &AgentConfig,
    workspace_path: &Path,
    prompt: &str,
    files: &[String],
    json_mode: bool,
) -> Result<(), ApiError> {
    let ws = Workspace::detect(workspace_path)?;
    let audit = AuditTrail::default_path().ok().map(AuditTrail::new);
    let ctx = ToolContext::new(ws, config.clone(), audit);

    let mut assembled = String::new();
    if !files.is_empty() {
        assembled.push_str("Contexto autorizado do workspace:\n");
        for path in files {
            let snap = ctx.read_file(path)?;
            if !json_mode {
                eprintln!("[contexto] {} ({} bytes)", snap.relative_path, snap.bytes);
            }
            let _ = write!(
                assembled,
                "\n--- Arquivo: {} ---\n{}\n",
                snap.relative_path, snap.content
            );
        }
        assembled.push_str("\nPergunta:\n");
    }
    assembled.push_str(prompt);

    let _ = cmd_chat(
        client, store, config, &assembled, None, json_mode, json_mode,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_fix(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    config: &AgentConfig,
    workspace_path: &Path,
    project_id: &str,
    goal: &str,
    files: &[String],
    json_mode: bool,
) -> Result<(), ApiError> {
    let session = require_valid_session(client, store).await?;
    let ws = Workspace::detect(workspace_path)?;
    let audit = AuditTrail::default_path().ok().map(AuditTrail::new);
    let ctx = ToolContext::new(ws, config.clone(), audit);

    let mut snapshots = Vec::new();
    for path in files {
        let snap = ctx.read_file(path)?;
        snapshots.push(WorkspaceFileSnapshotRequest {
            relative_path: snap.relative_path,
            content: snap.content,
        });
    }

    let req = CreateAgentRunRequest {
        goal: goal.to_owned(),
        model_id: config.default_model_id.clone(),
        workspace_files: snapshots,
        include_project_rag: true,
        rag_top_k: Some(6),
    };
    let detail = client
        .create_agent_run(&session.access_token, project_id, &req)
        .await?;

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&detail).unwrap_or_default()
        );
    } else {
        println!("Agent Run: {} ({})", detail.run.id, detail.run.status);
        if let Some(summary) = detail.run.plan_summary {
            println!("\nPlano:\n{summary}");
        }
        println!("\nPropostas ({}):", detail.proposals.len());
        for p in detail.proposals {
            println!(
                "  #{} [{}] {} target={:?} policy={} approval={}",
                p.step_index,
                p.tool_name,
                p.rationale.as_deref().unwrap_or(""),
                p.target_path,
                p.policy_decision,
                p.approval_status
            );
        }
    }
    Ok(())
}

pub fn cmd_diff(
    config: &AgentConfig,
    workspace_path: &Path,
    target_file: &str,
    new_content_file: &Path,
    out_proposal: Option<&Path>,
    json_mode: bool,
) -> Result<(), ApiError> {
    let ws = Workspace::detect(workspace_path)?;
    let audit = AuditTrail::default_path().ok().map(AuditTrail::new);
    let ctx = ToolContext::new(ws, config.clone(), audit);
    let new_content = std::fs::read_to_string(new_content_file).map_err(CoreError::from)?;
    let proposal = ctx.propose_patch(target_file, &new_content)?;

    if let Some(dest) = out_proposal {
        let raw = serde_json::to_string_pretty(&proposal)
            .map_err(|e| CoreError::Validation(e.to_string()))?;
        std::fs::write(dest, raw).map_err(CoreError::from)?;
    }

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&proposal).unwrap_or_default()
        );
    } else {
        println!("{}", proposal.unified_diff);
        println!("Approval hash: {}", proposal.approval_hash);
    }
    Ok(())
}

pub fn cmd_apply(
    config: &AgentConfig,
    workspace_path: &Path,
    proposal_file: &Path,
    yes: bool,
    json_mode: bool,
) -> Result<(), ApiError> {
    let ws = Workspace::detect(workspace_path)?;
    let audit = AuditTrail::default_path().ok().map(AuditTrail::new);
    let ctx = ToolContext::new(ws, config.clone(), audit);
    let raw = std::fs::read_to_string(proposal_file).map_err(CoreError::from)?;
    let proposal: PatchProposal =
        serde_json::from_str(&raw).map_err(|e| CoreError::Validation(e.to_string()))?;

    if !yes {
        println!("{}", proposal.unified_diff);
        eprint!(
            "Aplicar patch em '{}' (hash {})? [s/N]: ",
            proposal.relative_path,
            &proposal.approval_hash[..12]
        );
        io::stderr().flush().ok();
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(CoreError::from)?;
        if !matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "s" | "y" | "sim" | "yes"
        ) {
            return Err(ApiError::Cancelled);
        }
    }

    let grant = ApprovalGrant::issue(
        Uuid::new_v4().to_string(),
        None,
        &proposal.approval_hash,
        "local-cli-user",
        120,
    );
    let result = ctx.apply_patch(&proposal, &grant)?;
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        println!(
            "Patch aplicado em {} (sha256={}).",
            result.relative_path, result.new_sha256
        );
    }
    Ok(())
}

pub async fn cmd_test(
    config: &AgentConfig,
    workspace_path: &Path,
    command: &str,
    json_mode: bool,
) -> Result<(), ApiError> {
    let ws = Workspace::detect(workspace_path)?;
    let audit = AuditTrail::default_path().ok().map(AuditTrail::new);
    let ctx = ToolContext::new(ws, config.clone(), audit);
    let out = ctx.run_tests(command, None).await?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        print!("{}", out.stdout);
        eprint!("{}", out.stderr);
        if out.timed_out {
            eprintln!("Comando excedeu timeout.");
        }
    }
    if out.exit_code != 0 {
        return Err(ApiError::Core(CoreError::Validation(format!(
            "testes falharam com exit code {}",
            out.exit_code
        ))));
    }
    Ok(())
}

pub async fn cmd_tasks_list(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    limit: u32,
    json_mode: bool,
) -> Result<(), ApiError> {
    let session = require_valid_session(client, store).await?;
    let tasks = client.list_tasks(&session.access_token, limit).await?;
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&tasks).unwrap_or_default()
        );
    } else if tasks.items.is_empty() {
        println!("Nenhuma tarefa remota encontrada.");
    } else {
        for t in tasks.items {
            println!("{} | {:<18} | {}", t.id, t.status, t.title);
        }
    }
    Ok(())
}

pub async fn cmd_task_status(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    task_id: &str,
    json_mode: bool,
) -> Result<(), ApiError> {
    let session = require_valid_session(client, store).await?;
    let detail = client.get_task(&session.access_token, task_id).await?;
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&detail).unwrap_or_default()
        );
    } else {
        println!(
            "Task {} | {} | {}",
            detail.task.id, detail.task.status, detail.task.title
        );
        if let Some(summary) = detail.task.result_summary {
            println!("Resumo: {summary}");
        }
        println!("Eventos ({}):", detail.events.len());
        for ev in detail.events {
            println!("  [{}] {} - {}", ev.event_type, ev.created_at, ev.message);
        }
        if !detail.approvals.is_empty() {
            println!("Aprovacoes ({}):", detail.approvals.len());
            for ap in detail.approvals {
                println!(
                    "  {} | {} | {} | expira {}",
                    ap.id, ap.tool_name, ap.status, ap.expires_at
                );
            }
        }
    }
    Ok(())
}

pub async fn cmd_task_decision(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    task_id: &str,
    approval_id: &str,
    action: &str,
    json_mode: bool,
) -> Result<(), ApiError> {
    let session = require_valid_session(client, store).await?;
    let res = client
        .decide_approval(&session.access_token, task_id, approval_id, action)
        .await?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
    } else {
        println!(
            "Aprovacao {} marcada como {} (task={}).",
            res.approval.id, res.approval.status, res.task.status
        );
    }
    Ok(())
}

pub async fn cmd_remote_pair(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    config: &mut AgentConfig,
    config_path: &Path,
    device_name: Option<String>,
    pairing_code: Option<String>,
    json_mode: bool,
) -> Result<(), ApiError> {
    let code = if let Some(c) = pairing_code {
        c
    } else {
        let session = require_valid_session(client, store).await?;
        let name = device_name.unwrap_or_else(default_device_name);
        let platform = std::env::consts::OS.to_owned();
        let challenge = client
            .create_pairing_challenge(&session.access_token, &name, &platform)
            .await?;
        challenge.pairing_code
    };

    let completed = client.complete_pairing(&code).await?;
    store.save_device_token(&completed.device_token)?;
    config.runner.device_id = Some(completed.device.id.clone());
    config.runner.device_name = Some(completed.device.name.clone());
    config.save(config_path)?;

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "paired": true,
                "device": completed.device
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "Dispositivo '{}' ({}) pareado com sucesso! Credencial salva no keyring do sistema.",
            completed.device.name, completed.device.id
        );
    }
    Ok(())
}

pub async fn cmd_remote_status(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    config: &AgentConfig,
    json_mode: bool,
) -> Result<(), ApiError> {
    let has_local_token = store.load_device_token()?.is_some();
    let devices = if let Ok(session) = require_valid_session(client, store).await {
        client.list_devices(&session.access_token).await.ok()
    } else {
        None
    };

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "localDeviceId": config.runner.device_id,
                "localDeviceName": config.runner.device_name,
                "deviceTokenStored": has_local_token,
                "devices": devices.map(|d| d.items)
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "Runner local: device_id={} | token_no_keyring={}",
            config
                .runner
                .device_id
                .as_deref()
                .unwrap_or("(nao pareado)"),
            has_local_token
        );
        if let Some(list) = devices {
            for d in list.items {
                println!(
                    "  {} | {} ({}) | status={} online={}",
                    d.id, d.name, d.platform, d.status, d.online
                );
            }
        }
    }
    Ok(())
}

pub async fn cmd_remote_revoke(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
    config: &mut AgentConfig,
    config_path: &Path,
    device_id: Option<String>,
    json_mode: bool,
) -> Result<(), ApiError> {
    let target_id = device_id.or_else(|| config.runner.device_id.clone());
    if let Some(id) = target_id.as_deref()
        && let Ok(session) = require_valid_session(client, store).await
    {
        let _ = client.revoke_device(&session.access_token, id).await?;
    }
    store.clear_device_token()?;
    config.runner.device_id = None;
    config.save(config_path)?;
    if json_mode {
        println!("{}", json!({ "revoked": true, "deviceId": target_id }));
    } else {
        println!("Vinculo remoto revogado e credencial local removida.");
    }
    Ok(())
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| format!("creatingj-{}", std::env::consts::OS))
}

fn urlencoding_basic(input: &str) -> String {
    input
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace(' ', "%20")
}
