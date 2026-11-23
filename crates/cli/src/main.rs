mod commands;
mod session;

use clap::{Parser, Subcommand};
use creatingj_api_client::CreatingJClient;
use creatingj_audit::init_tracing;
use creatingj_auth::KeyringCredentialStore;
use creatingj_core::AgentConfig;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "creatingj",
    version,
    about = "CreatingJ CLI — Agente de programacao no terminal. Nao existe limite para sua imaginacao."
)]
struct Cli {
    #[arg(long, global = true, env = "CREATINGJ_API_URL")]
    api_url: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, short, global = true)]
    verbose: bool,

    #[arg(long, global = true)]
    workspace: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Login {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        pkce_web_url: Option<String>,
    },
    Logout,
    Whoami,
    Status,
    Chat {
        prompt: String,
        #[arg(long)]
        conversation: Option<String>,
        #[arg(long)]
        sync: bool,
    },
    Ask {
        prompt: String,
        #[arg(long = "file", short = 'f')]
        files: Vec<String>,
    },
    Fix {
        #[arg(long)]
        project: String,
        goal: String,
        #[arg(long = "file", short = 'f')]
        files: Vec<String>,
    },
    Diff {
        file: String,
        #[arg(long)]
        content_file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Apply {
        proposal: PathBuf,
        #[arg(long, short = 'y')]
        yes: bool,
    },
    Test {
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
    Tasks {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    Task {
        #[command(subcommand)]
        action: TaskCommands,
    },
    Remote {
        #[command(subcommand)]
        action: RemoteCommands,
    },
}

#[derive(Debug, Subcommand)]
enum TaskCommands {
    Status {
        task_id: String,
    },
    Cancel {
        task_id: String,
    },
    Approve {
        task_id: String,
        approval_id: String,
    },
    Reject {
        task_id: String,
        approval_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum RemoteCommands {
    Pair {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        code: Option<String>,
    },
    Status,
    Revoke {
        #[arg(long)]
        device_id: Option<String>,
    },
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
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

    let client = match CreatingJClient::from_config(&config) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Erro: {err}");
            return ExitCode::from(err.exit_code() as u8);
        }
    };

    let workspace_path = cli
        .workspace
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let store = KeyringCredentialStore;

    let result = match cli.command {
        None => commands::cmd_interactive(&client, &store, &config, &workspace_path).await,
        Some(Commands::Login {
            email,
            password_stdin,
            pkce_web_url,
        }) => {
            commands::cmd_login(
                &client,
                &store,
                email,
                password_stdin,
                pkce_web_url,
                cli.json,
            )
            .await
        }
        Some(Commands::Logout) => commands::cmd_logout(&client, &store, cli.json).await,
        Some(Commands::Whoami) => commands::cmd_whoami(&client, &store, cli.json).await,
        Some(Commands::Status) => commands::cmd_status(&client, &workspace_path, cli.json).await,
        Some(Commands::Chat {
            prompt,
            conversation,
            sync,
        }) => commands::cmd_chat(
            &client,
            &store,
            &config,
            &prompt,
            conversation,
            sync,
            cli.json,
        )
        .await
        .map(|_| ()),
        Some(Commands::Ask { prompt, files }) => {
            commands::cmd_ask(
                &client,
                &store,
                &config,
                &workspace_path,
                &prompt,
                &files,
                cli.json,
            )
            .await
        }
        Some(Commands::Fix {
            project,
            goal,
            files,
        }) => {
            commands::cmd_fix(
                &client,
                &store,
                &config,
                &workspace_path,
                &project,
                &goal,
                &files,
                cli.json,
            )
            .await
        }
        Some(Commands::Diff {
            file,
            content_file,
            out,
        }) => commands::cmd_diff(
            &config,
            &workspace_path,
            &file,
            &content_file,
            out.as_deref(),
            cli.json,
        ),
        Some(Commands::Apply { proposal, yes }) => {
            commands::cmd_apply(&config, &workspace_path, &proposal, yes, cli.json)
        }
        Some(Commands::Test { command }) => {
            let joined = command.join(" ");
            commands::cmd_test(&config, &workspace_path, &joined, cli.json).await
        }
        Some(Commands::Tasks { limit }) => {
            commands::cmd_tasks_list(&client, &store, limit, cli.json).await
        }
        Some(Commands::Task { action }) => match action {
            TaskCommands::Status { task_id } => {
                commands::cmd_task_status(&client, &store, &task_id, cli.json).await
            }
            TaskCommands::Cancel { task_id } => {
                let s = session::require_valid_session(&client, &store).await;
                match s {
                    Ok(sess) => client.cancel_task(&sess.access_token, &task_id).await,
                    Err(e) => Err(e),
                }
            }
            TaskCommands::Approve {
                task_id,
                approval_id,
            } => {
                commands::cmd_task_decision(
                    &client,
                    &store,
                    &task_id,
                    &approval_id,
                    "APPROVE",
                    cli.json,
                )
                .await
            }
            TaskCommands::Reject {
                task_id,
                approval_id,
            } => {
                commands::cmd_task_decision(
                    &client,
                    &store,
                    &task_id,
                    &approval_id,
                    "REJECT",
                    cli.json,
                )
                .await
            }
        },
        Some(Commands::Remote { action }) => match action {
            RemoteCommands::Pair { name, code } => {
                commands::cmd_remote_pair(
                    &client,
                    &store,
                    &mut config,
                    &config_path,
                    name,
                    code,
                    cli.json,
                )
                .await
            }
            RemoteCommands::Status => {
                commands::cmd_remote_status(&client, &store, &config, cli.json).await
            }
            RemoteCommands::Revoke { device_id } => {
                commands::cmd_remote_revoke(
                    &client,
                    &store,
                    &mut config,
                    &config_path,
                    device_id,
                    cli.json,
                )
                .await
            }
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if cli.json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "error": err.to_string(),
                        "exitCode": err.exit_code().as_i32()
                    })
                );
            } else {
                eprintln!("Erro: {err}");
            }
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
