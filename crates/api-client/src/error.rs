use creatingj_core::{CoreError, ExitCode};
use creatingj_protocol::ProblemDetail;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("nao autenticado ou sessao expirada: {0}")]
    Unauthorized(String),
    #[error("acesso negado: {0}")]
    Forbidden(String),
    #[error("limite de requisicoes atingido (429): {message}")]
    RateLimited {
        retry_after_secs: Option<u64>,
        message: String,
    },
    #[error("erro da API ({status}): {}", problem.display_message())]
    Problem {
        status: u16,
        problem: Box<ProblemDetail>,
    },
    #[error("erro HTTP ({status}): {message}")]
    Http { status: u16, message: String },
    #[error("erro de rede: {0}")]
    Network(String),
    #[error("resposta invalida da API: {0}")]
    InvalidResponse(String),
    #[error("operacao cancelada")]
    Cancelled,
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl ApiError {
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::Unauthorized(_) => ExitCode::AuthRequired,
            Self::Forbidden(_) => ExitCode::PermissionDenied,
            Self::Network(_) | Self::RateLimited { .. } => ExitCode::NetworkError,
            Self::Cancelled => ExitCode::Cancelled,
            Self::Core(c) => c.exit_code(),
            Self::Problem { .. } | Self::Http { .. } | Self::InvalidResponse(_) => {
                ExitCode::GeneralError
            }
        }
    }
}
