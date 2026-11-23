pub mod error;
pub mod runner;
pub mod sse;

use creatingj_core::AgentConfig;
use creatingj_protocol::{
    AgentRunDetailResponse, CompletePairingRequest, CompletePairingResponse,
    ConversationHistoryResponse, ConversationSummaryResponse, ConversationsPageResponse,
    CreateAgentRunRequest, CreateConversationRequest, CreatePairingChallengeRequest,
    CurrentUserResponse, DeviceSummaryResponse, DevicesResponse, LoginRequest, LoginResponse,
    MessageExchangeResponse, PairingChallengeResponse, PkceAuthorizeRequest, PkceAuthorizeResponse,
    PkceTokenRequest, ProjectsPageResponse, RefreshTokenRequest, RemoteTaskDetailResponse,
    RemoteTasksResponse, SendMessageRequest, SseFrame, SystemStatusResponse, TokenPairResponse,
    ToolApprovalDecisionRequest, ToolApprovalDecisionResponse,
};
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use std::time::Duration;

pub use error::ApiError;
pub use runner::RunnerClient;

#[derive(Debug, Clone)]
pub struct CreatingJClient {
    base_url: String,
    http: Client,
    stream_http: Client,
}

impl CreatingJClient {
    pub fn from_config(config: &AgentConfig) -> Result<Self, ApiError> {
        config.validate()?;
        let http = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .user_agent(concat!("creatingj-agent/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ApiError::Network(format!("falha ao criar cliente HTTP: {e}")))?;

        let stream_http = Client::builder()
            .connect_timeout(Duration::from_secs(config.request_timeout_secs))
            .timeout(Duration::from_secs(config.stream_timeout_secs))
            .user_agent(concat!("creatingj-agent/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ApiError::Network(format!("falha ao criar cliente SSE: {e}")))?;

        Ok(Self {
            base_url: config.api_base_url.trim_end_matches('/').to_owned(),
            http,
            stream_http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn system_status(&self) -> Result<SystemStatusResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint("/api/v1/system/status"))
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/auth/login"))
            .json(&LoginRequest {
                email: email.to_owned(),
                password: password.to_owned(),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn pkce_authorize(
        &self,
        access_token: &str,
        req: &PkceAuthorizeRequest,
    ) -> Result<PkceAuthorizeResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/auth/pkce/authorize"))
            .bearer_auth(access_token)
            .json(req)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn pkce_exchange_token(
        &self,
        req: &PkceTokenRequest,
    ) -> Result<TokenPairResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/auth/pkce/token"))
            .json(req)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPairResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/auth/token/refresh"))
            .json(&RefreshTokenRequest {
                refresh_token: refresh_token.to_owned(),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn logout(&self, access_token: &str) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/auth/logout"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        expect_success(resp).await
    }

    pub async fn me(&self, access_token: &str) -> Result<CurrentUserResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint("/api/v1/auth/me"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn list_conversations(
        &self,
        access_token: &str,
        page: u32,
        size: u32,
    ) -> Result<ConversationsPageResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint(&format!("/api/v1/conversations?page={page}&size={size}")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn create_conversation(
        &self,
        access_token: &str,
        title: &str,
        model_id: Option<&str>,
    ) -> Result<ConversationSummaryResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/conversations"))
            .bearer_auth(access_token)
            .json(&CreateConversationRequest {
                title: title.to_owned(),
                model_id: model_id.map(str::to_owned),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn get_conversation(
        &self,
        access_token: &str,
        conversation_id: &str,
    ) -> Result<ConversationHistoryResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint(&format!("/api/v1/conversations/{conversation_id}")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn send_message(
        &self,
        access_token: &str,
        conversation_id: &str,
        content: &str,
    ) -> Result<MessageExchangeResponse, ApiError> {
        let resp = self
            .stream_http
            .post(self.endpoint(&format!("/api/v1/conversations/{conversation_id}/messages")))
            .bearer_auth(access_token)
            .json(&SendMessageRequest {
                content: content.to_owned(),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn stream_message<F>(
        &self,
        access_token: &str,
        conversation_id: &str,
        content: &str,
        on_frame: F,
    ) -> Result<(), ApiError>
    where
        F: FnMut(SseFrame) -> Result<(), ApiError>,
    {
        let resp = self
            .stream_http
            .post(self.endpoint(&format!(
                "/api/v1/conversations/{conversation_id}/messages/stream"
            )))
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .json(&SendMessageRequest {
                content: content.to_owned(),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;

        if !resp.status().is_success() {
            return Err(parse_error(resp).await);
        }

        sse::consume_sse_stream(resp, on_frame).await
    }

    pub async fn cancel_generation(
        &self,
        access_token: &str,
        conversation_id: &str,
        generation_id: &str,
    ) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.endpoint(&format!(
                "/api/v1/conversations/{conversation_id}/generations/{generation_id}/cancel"
            )))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        expect_success(resp).await
    }

    pub async fn list_projects(
        &self,
        access_token: &str,
    ) -> Result<ProjectsPageResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint("/api/v1/projects"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn create_agent_run(
        &self,
        access_token: &str,
        project_id: &str,
        req: &CreateAgentRunRequest,
    ) -> Result<AgentRunDetailResponse, ApiError> {
        let resp = self
            .stream_http
            .post(self.endpoint(&format!("/api/v1/projects/{project_id}/agent/runs")))
            .bearer_auth(access_token)
            .json(req)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn list_devices(&self, access_token: &str) -> Result<DevicesResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint("/api/v1/devices"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn create_pairing_challenge(
        &self,
        access_token: &str,
        device_name: &str,
        platform: &str,
    ) -> Result<PairingChallengeResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/devices/pairing-challenges"))
            .bearer_auth(access_token)
            .json(&CreatePairingChallengeRequest {
                device_name: device_name.to_owned(),
                platform: platform.to_owned(),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn complete_pairing(
        &self,
        pairing_code: &str,
    ) -> Result<CompletePairingResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/runner/pair/complete"))
            .json(&CompletePairingRequest {
                pairing_code: pairing_code.to_owned(),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn revoke_device(
        &self,
        access_token: &str,
        device_id: &str,
    ) -> Result<DeviceSummaryResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint(&format!("/api/v1/devices/{device_id}/revoke")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn list_tasks(
        &self,
        access_token: &str,
        limit: u32,
    ) -> Result<RemoteTasksResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint(&format!("/api/v1/tasks?limit={limit}")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn get_task(
        &self,
        access_token: &str,
        task_id: &str,
    ) -> Result<RemoteTaskDetailResponse, ApiError> {
        let resp = self
            .http
            .get(self.endpoint(&format!("/api/v1/tasks/{task_id}")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn cancel_task(&self, access_token: &str, task_id: &str) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.endpoint(&format!("/api/v1/tasks/{task_id}/cancel")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        expect_success(resp).await
    }

    pub async fn decide_approval(
        &self,
        access_token: &str,
        task_id: &str,
        approval_id: &str,
        action: &str,
    ) -> Result<ToolApprovalDecisionResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint(&format!(
                "/api/v1/tasks/{task_id}/approvals/{approval_id}/decision"
            )))
            .bearer_auth(access_token)
            .json(&ToolApprovalDecisionRequest {
                action: action.to_owned(),
            })
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn map_reqwest_err(err: reqwest::Error) -> ApiError {
    if err.is_timeout() {
        ApiError::Network("tempo limite de conexao com a API CreatingJ excedido".to_owned())
    } else if err.is_connect() {
        ApiError::Network("nao foi possivel conectar ao servidor CreatingJ".to_owned())
    } else {
        ApiError::Network(format!("erro de transporte HTTP: {err}"))
    }
}

pub(crate) async fn expect_success(resp: Response) -> Result<(), ApiError> {
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

pub(crate) async fn parse_json<T: DeserializeOwned>(resp: Response) -> Result<T, ApiError> {
    if !resp.status().is_success() {
        return Err(parse_error(resp).await);
    }
    resp.json::<T>()
        .await
        .map_err(|e| ApiError::InvalidResponse(format!("resposta JSON invalida: {e}")))
}

pub(crate) async fn parse_error(resp: Response) -> ApiError {
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let body = resp.text().await.unwrap_or_default();
    let parsed_problem = serde_json::from_str::<creatingj_protocol::ProblemDetail>(&body).ok();
    let message = parsed_problem.as_ref().map_or_else(
        || {
            if body.trim().is_empty() {
                format!("HTTP {}", status.as_u16())
            } else {
                body.chars().take(240).collect()
            }
        },
        creatingj_protocol::ProblemDetail::display_message,
    );

    match status {
        StatusCode::UNAUTHORIZED => ApiError::Unauthorized(message),
        StatusCode::FORBIDDEN => ApiError::Forbidden(message),
        StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited {
            retry_after_secs: retry_after,
            message,
        },
        _ => match parsed_problem {
            Some(problem) => ApiError::Problem {
                status: status.as_u16(),
                problem: Box::new(problem),
            },
            None => ApiError::Http {
                status: status.as_u16(),
                message,
            },
        },
    }
}
