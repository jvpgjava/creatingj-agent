mod daemon;
mod executor;
mod lock;

use clap::{Parser, Subcommand};
use creatingj_api_client::RunnerClient;
use creatingj_audit::init_tracing;
use creatingj_auth::{CredentialStore, KeyringCredentialStore};
use creatingj_core::AgentConfig;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "creatingj-runner",
    version,
    about = "CreatingJ Runner — Servico local seguro para execucao de tarefas remotas autorizadas."
)]
struct RunnerCli {
    #[arg(long, global = true, env = "CREATINGJ_API_URL")]
    api_url: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, short, global = true)]
    verbose: bool,

    #[arg(long, global = true)]
    workspace: Option<PathBuf>,

    #[command(subcommand)]
    command: RunnerCommands,
}

#[derive(Debug, Subcommand)]
enum RunnerCommands {
    Run {
        #[arg(long)]
        once: bool,
        #[arg(long, env = "CREATINGJ_DEVICE_TOKEN")]
        device_token: Option<String>,
    },
    Pair {
        #[arg(long)]
        code: String,
    },
    Status,
    PrintSystemdUnit,
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> ExitCode {
    let cli = RunnerCli::parse();
    init_tracing(cli.json, cli.verbose);

    let config_path = match AgentConfig::default_config_path() {
        Ok(p) => p,
        Err(err) => {
            eprintln!("Erro: {err}");
            return ExitCode::from(err.exit_code() as u8);
        }
    };
    let mut config = match AgentConfig::load_or_default(&config_path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Erro: {err}");
            return ExitCode::from(err.exit_code() as u8);
        }
    };
    if let Some(url) = cli.api_url {
        config.api_base_url = url;
    }

    let client = match RunnerClient::from_config(&config) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Erro: {err}");
            return ExitCode::from(err.exit_code() as u8);
        }
    };

    let store = KeyringCredentialStore;
    let workspace_path = cli
        .workspace
        .or_else(|| config.runner.workspace_root.clone())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let res = match cli.command {
        RunnerCommands::Run { once, device_token } => {
            let Some(token) = device_token.or_else(|| store.load_device_token().ok().flatten())
            else {
                eprintln!(
                    "Erro: nenhum device token encontrado; execute `creatingj remote pair` ou `creatingj-runner pair --code <CODIGO>`"
                );
                return ExitCode::from(creatingj_core::ExitCode::AuthRequired as u8);
            };
            daemon::run_daemon(&client, &token, &config, &workspace_path, once).await
        }
        RunnerCommands::Pair { code } => match client.complete_pairing(&code).await {
            Ok(resp) => {
                if let Err(err) = store.save_device_token(&resp.device_token) {
                    Err(creatingj_api_client::ApiError::Core(err))
                } else {
                    config.runner.device_id = Some(resp.device.id.clone());
                    config.runner.device_name = Some(resp.device.name.clone());
                    config.runner.workspace_root = Some(workspace_path);
                    let _ = config.save(&config_path);
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "paired": true,
                                "device": resp.device
                            }))
                            .unwrap_or_default()
                        );
                    } else {
                        println!(
                            "Runner pareado como '{}' ({}).",
                            resp.device.name, resp.device.id
                        );
                    }
                    Ok(())
                }
            }
            Err(err) => Err(err),
        },
        RunnerCommands::Status => {
            let has_token = store.load_device_token().ok().flatten().is_some();
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "deviceId": config.runner.device_id,
                        "deviceName": config.runner.device_name,
                        "workspace": workspace_path,
                        "tokenConfigured": has_token
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!(
                    "Runner status: device_id={} | workspace={} | token_configurado={}",
                    config
                        .runner
                        .device_id
                        .as_deref()
                        .unwrap_or("(nao pareado)"),
                    workspace_path.display(),
                    has_token
                );
            }
            Ok(())
        }
        RunnerCommands::PrintSystemdUnit => {
            println!(
                "[Unit]\nDescription=CreatingJ Local Runner\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart=%h/.local/bin/creatingj-runner run --workspace %h/projects\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target"
            );
            Ok(())
        }
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Erro: {err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
