use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: String,
    pub user_id: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPairResponse {
    pub access_token: String,
    pub token_type: String,
    pub access_token_expires_at: String,
    pub refresh_token: String,
    pub refresh_token_expires_at: String,
    pub user_id: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkceAuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkceAuthorizeResponse {
    pub authorization_code: String,
    pub redirect_uri: String,
    pub state: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkceTokenRequest {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentUserResponse {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub roles: Vec<String>,
    pub session_id: Option<String>,
    pub client_id: Option<String>,
    pub session_expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummaryResponse {
    pub id: String,
    pub client_id: Option<String>,
    pub auth_method: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}
