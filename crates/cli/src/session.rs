use creatingj_api_client::{ApiError, CreatingJClient};
use creatingj_auth::{CredentialStore, StoredSession};
use creatingj_core::CoreError;

pub async fn require_valid_session(
    client: &CreatingJClient,
    store: &dyn CredentialStore,
) -> Result<StoredSession, ApiError> {
    let session = store.load_session()?.ok_or_else(|| {
        ApiError::Unauthorized(
            "nenhuma sessao ativa; execute `creatingj login` primeiro".to_owned(),
        )
    })?;

    match client.me(&session.access_token).await {
        Ok(_) => Ok(session),
        Err(ApiError::Unauthorized(_)) => {
            if let Some(refresh) = session.refresh_token.as_deref() {
                let refreshed = client.refresh_token(refresh).await?;
                let updated = StoredSession {
                    access_token: refreshed.access_token,
                    refresh_token: Some(refreshed.refresh_token),
                    expires_at: refreshed.access_token_expires_at,
                    user_id: refreshed.user_id,
                    email: refreshed.email,
                    roles: refreshed.roles,
                };
                store.save_session(&updated)?;
                Ok(updated)
            } else {
                Err(ApiError::Unauthorized(
                    "sessao expirada; execute `creatingj login` novamente".to_owned(),
                ))
            }
        }
        Err(err) => Err(err),
    }
}

pub fn read_password_from_stdin() -> Result<String, CoreError> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_owned();
    if trimmed.is_empty() {
        return Err(CoreError::Validation("senha vazia".to_owned()));
    }
    Ok(trimmed)
}
