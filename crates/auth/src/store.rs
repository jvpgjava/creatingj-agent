use creatingj_core::CoreError;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

const SERVICE_NAME: &str = "creatingj-agent";
const SESSION_ACCOUNT: &str = "user-session";
const DEVICE_TOKEN_ACCOUNT: &str = "runner-device-token";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: String,
    pub user_id: String,
    pub email: String,
    pub roles: Vec<String>,
}

pub trait CredentialStore: Send + Sync {
    fn save_session(&self, session: &StoredSession) -> Result<(), CoreError>;
    fn load_session(&self) -> Result<Option<StoredSession>, CoreError>;
    fn clear_session(&self) -> Result<(), CoreError>;

    fn save_device_token(&self, token: &str) -> Result<(), CoreError>;
    fn load_device_token(&self) -> Result<Option<String>, CoreError>;
    fn clear_device_token(&self) -> Result<(), CoreError>;
}

#[derive(Debug, Default, Clone)]
pub struct KeyringCredentialStore;

impl KeyringCredentialStore {
    fn entry(account: &str) -> Result<keyring::Entry, CoreError> {
        keyring::Entry::new(SERVICE_NAME, account).map_err(|e| {
            CoreError::AuthRequired(format!("falha ao acessar keyring do sistema: {e}"))
        })
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn save_session(&self, session: &StoredSession) -> Result<(), CoreError> {
        let encoded = serde_json::to_string(session)
            .map_err(|e| CoreError::Validation(format!("falha ao serializar sessao: {e}")))?;
        Self::entry(SESSION_ACCOUNT)?
            .set_password(&encoded)
            .map_err(|e| CoreError::AuthRequired(format!("falha ao salvar sessao no keyring: {e}")))
    }

    fn load_session(&self) -> Result<Option<StoredSession>, CoreError> {
        match Self::entry(SESSION_ACCOUNT)?.get_password() {
            Ok(raw) => {
                let session: StoredSession = serde_json::from_str(&raw).map_err(|e| {
                    CoreError::AuthRequired(format!("sessao corrompida no keyring: {e}"))
                })?;
                Ok(Some(session))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CoreError::AuthRequired(format!(
                "falha ao ler sessao do keyring: {e}"
            ))),
        }
    }

    fn clear_session(&self) -> Result<(), CoreError> {
        match Self::entry(SESSION_ACCOUNT)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CoreError::AuthRequired(format!(
                "falha ao remover sessao do keyring: {e}"
            ))),
        }
    }

    fn save_device_token(&self, token: &str) -> Result<(), CoreError> {
        Self::entry(DEVICE_TOKEN_ACCOUNT)?
            .set_password(token)
            .map_err(|e| {
                CoreError::AuthRequired(format!("falha ao salvar device token no keyring: {e}"))
            })
    }

    fn load_device_token(&self) -> Result<Option<String>, CoreError> {
        match Self::entry(DEVICE_TOKEN_ACCOUNT)?.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CoreError::AuthRequired(format!(
                "falha ao ler device token do keyring: {e}"
            ))),
        }
    }

    fn clear_device_token(&self) -> Result<(), CoreError> {
        match Self::entry(DEVICE_TOKEN_ACCOUNT)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CoreError::AuthRequired(format!(
                "falha ao remover device token do keyring: {e}"
            ))),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryCredentialStore {
    session: Arc<Mutex<Option<StoredSession>>>,
    device_token: Arc<Mutex<Option<String>>>,
}

impl CredentialStore for InMemoryCredentialStore {
    fn save_session(&self, session: &StoredSession) -> Result<(), CoreError> {
        *self.session.lock().expect("lock") = Some(session.clone());
        Ok(())
    }

    fn load_session(&self) -> Result<Option<StoredSession>, CoreError> {
        Ok(self.session.lock().expect("lock").clone())
    }

    fn clear_session(&self) -> Result<(), CoreError> {
        *self.session.lock().expect("lock") = None;
        Ok(())
    }

    fn save_device_token(&self, token: &str) -> Result<(), CoreError> {
        *self.device_token.lock().expect("lock") = Some(token.to_owned());
        Ok(())
    }

    fn load_device_token(&self) -> Result<Option<String>, CoreError> {
        Ok(self.device_token.lock().expect("lock").clone())
    }

    fn clear_device_token(&self) -> Result<(), CoreError> {
        *self.device_token.lock().expect("lock") = None;
        Ok(())
    }
}
