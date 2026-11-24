<p align="center">
  <img src=".github/assets/creatingj-mascote-cli.png" alt="Mascote CreatingJ CLI" width="220" />
</p>

<h1 align="center">CreatingJ CLI &amp; Runner</h1>

<p align="center">
  <strong>Não existe limite para sua imaginação.</strong>
</p>

<p align="center">
  Agente de programação no terminal e runner local seguro da plataforma <strong>CreatingJ</strong>, escrito em Rust.
</p>

---

## Sumário

- [Visão geral](#visão-geral)
- [Executáveis](#executáveis)
- [Instalação e build](#instalação-e-build)
- [Comandos principais](#comandos-principais)
- [Segurança por padrão](#segurança-por-padrão)
- [Estrutura do workspace](#estrutura-do-workspace)
- [Qualidade e testes](#qualidade-e-testes)
- [Autor](#autor)

---

## Visão geral

O **CreatingJ Agent** leva a experiência de IA de código diretamente para o seu terminal e permite executar tarefas autorizadas disparadas pela web, mobile, IDE ou extensão VS Code — mantendo o seu código e o seu ambiente sempre sob o seu controle.

- **Nenhuma chave de provedor de IA sai do servidor:** a CLI e o runner autenticam exclusivamente no backend CreatingJ.
- **Consentimento explícito:** alterações em arquivos e comandos externos exigem revisão e aprovação amarrada ao hash SHA-256 exato do diff/argumentos.
- **Isolamento de workspace:** canonicalização de caminhos, bloqueio de path traversal (`../`), symlinks fora da raiz e exclusão automática de `.env`, chaves privadas e credenciais.
- **Universal para qualquer linguagem:** suporte a detecção de stack e testes pré-aprovados para Rust, Java/Maven/Gradle, Node/TypeScript, Python, Go, .NET/C#, Ruby, PHP, Kotlin, Dart/Flutter, Swift e Zig.

---

## Executáveis

| Binário | Papel |
| --- | --- |
| `creatingj` | CLI interativa e não interativa (`--json`) para autenticação, chat com streaming SSE, contexto seguro, diffs/patches, testes e gestão de tarefas remotas. |
| `creatingj-runner` | Serviço local em segundo plano que mantém heartbeat, recebe tarefas remotas via lease autenticado (`X-Device-Token`), executa ferramentas autorizadas e envia eventos deduplicáveis. |

---

## Instalação e build

### Pré-requisitos

- **Rust** `1.85+` (`rustc`, `cargo`, `rustfmt`, `clippy`)
- **CreatingJ Backend** rodando localmente (`http://127.0.0.1:8080`) ou via HTTPS

### Compilar em modo release

```bash
cargo build --release --bin creatingj --bin creatingj-runner
```

Os binários gerados ficam em `target/release/creatingj` e `target/release/creatingj-runner`.

### Configuração

Por padrão, a configuração fica em `~/.creatingj/config.toml` e pode ser sobrescrita por variáveis de ambiente:

| Variável | Descrição | Padrão |
| --- | --- | --- |
| `CREATINGJ_API_URL` | URL base da API CreatingJ (HTTPS obrigatório fora de loopback local) | `http://127.0.0.1:8080` |
| `CREATINGJ_MODEL_ID` | Modelo padrão opcional para novas conversas | _(padrão do servidor)_ |
| `CREATINGJ_DEVICE_TOKEN` | Token de dispositivo opcional para o runner (preferencialmente armazenado no keyring do SO) | _(keyring)_ |

---

## Comandos principais

### Autenticação e sessão

```bash
creatingj login --email voce@exemplo.com         # login tradicional (salva no keyring do SO)
creatingj login --pkce-web-url https://app.creatingj.dev  # Authorization Code + PKCE S256
creatingj whoami                                 # exibe usuário e expiração sem vazar tokens
creatingj status                                 # valida backend e detecta workspace/stacks
creatingj logout                                 # revoga sessão e limpa keyring
```

### Chat e código no terminal

```bash
creatingj                                        # chat interativo no workspace atual (Ctrl+C cancela stream)
creatingj chat "Explique este projeto"           # pergunta com streaming SSE
creatingj chat --json "Resumo da arquitetura"    # saída JSON estruturada com exit codes estáveis
creatingj ask "Por que falha?" -f src/main.rs    # envia contexto explicitamente autorizado
creatingj fix --project <ID> "Corrigir bug" -f src/lib.rs
creatingj diff src/lib.rs --content-file novo.rs --out proposta.json
creatingj apply proposta.json                    # exige confirmação e valida conflito por SHA-256
creatingj test cargo test --workspace            # executa testes com timeout e saída redigida
```

### Controle remoto e runner local

```bash
creatingj remote pair --name "Meu-Notebook"      # pareia o computador e grava token no keyring
creatingj remote status                          # verifica estado do vínculo e dispositivos
creatingj remote revoke                          # revoga dispositivo e apaga credencial local

creatingj tasks                                  # lista tarefas remotas
creatingj task status <TASK_ID>                  # eventos e aprovações pendentes
creatingj task approve <TASK_ID> <APPROVAL_ID>   # aprova operação pendente
creatingj task reject <TASK_ID> <APPROVAL_ID>    # rejeita operação pendente

creatingj-runner run --workspace /caminho/projeto
creatingj-runner print-systemd-unit              # gera unit file systemd --user para Linux
```

---

## Segurança por padrão

- **Zero `unsafe`:** `[workspace.lints.rust] unsafe_code = "forbid"`.
- **Keyring nativo do SO:** tokens de usuário e `X-Device-Token` ficam no Windows Credential Manager, macOS Keychain ou Linux Secret Service.
- **Logs e auditoria redigidos:** `creatingj-audit` mascara `Bearer`, `X-Device-Token`, chaves `sk-*`/`crj_*`/`ghp_*`/`AKIA*` e chaves privadas antes de gravar em `~/.creatingj/audit.jsonl`.
- **Proteção contra conflitos e tampering:** todo patch verifica o hash SHA-256 base do arquivo antes de escrever e faz rollback automático em caso de erro de I/O.
- **Sem shell arbitrária:** subprocessos são invocados diretamente sem `sh -c`/`cmd /c`, sem variáveis de ambiente sensíveis, com timeout e `kill_on_drop(true)`.

---

## Estrutura do workspace

```text
creatingj-agent/
├── Cargo.toml
├── Jenkinsfile
└── crates/
    ├── core/          # Configuração tipada, erros e exit codes estáveis
    ├── audit/         # Redação de segredos e trilha JSONL
    ├── protocol/      # Contratos OpenAPI v1, SSE e Runner v1
    ├── permissions/   # Políticas determinísticas e consentimento por hash/TTL
    ├── workspace/     # Canonicalização, anti-traversal, .gitignore e snapshots
    ├── tools/         # Leitura, busca, diff/patch seguro e execução de testes
    ├── auth/          # PKCE S256 loopback e armazenamento no keyring do SO
    ├── api-client/    # Cliente HTTP/TLS, SSE UTF-8 e RunnerClient
    ├── cli/           # Binário `creatingj`
    └── runner/        # Binário `creatingj-runner`
```

---

## Qualidade e testes

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

---

## Autor

Criado por **João Vitor Prestes Grando** ([@jvpgjava](https://github.com/jvpgjava)).
