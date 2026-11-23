use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    GeneralError = 1,
    ValidationError = 2,
    AuthRequired = 3,
    PermissionDenied = 4,
    NetworkError = 5,
    Conflict = 6,
    Cancelled = 130,
}

impl ExitCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("configuracao invalida: {0}")]
    InvalidConfig(String),
    #[error("erro de entrada/validacao: {0}")]
    Validation(String),
    #[error("autenticacao necessaria ou sessao expirada: {0}")]
    AuthRequired(String),
    #[error("permissao negada: {0}")]
    PermissionDenied(String),
    #[error("conflito de estado: {0}")]
    Conflict(String),
    #[error("operacao cancelada")]
    Cancelled,
    #[error("erro de I/O: {0}")]
    Io(#[from] std::io::Error),
}

impl CoreError {
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidConfig(_) | Self::Validation(_) => ExitCode::ValidationError,
            Self::AuthRequired(_) => ExitCode::AuthRequired,
            Self::PermissionDenied(_) => ExitCode::PermissionDenied,
            Self::Conflict(_) => ExitCode::Conflict,
            Self::Cancelled => ExitCode::Cancelled,
            Self::Io(_) => ExitCode::GeneralError,
        }
    }
}
