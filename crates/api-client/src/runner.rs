use crate::error::ApiError;
use crate::{map_reqwest_err, parse_json};
use creatingj_core::AgentConfig;
use creatingj_protocol::{
    CompletePairingRequest, CompletePairingResponse, DeviceSummaryResponse,
    RemoteTaskSummaryResponse, RunnerApprovalRequest, RunnerCompleteTaskRequest,
    RunnerLeaseResponse, RunnerTaskEventRequest, RunnerTaskEventResponse, ToolApprovalResponse,
};
use reqwest::Client;
use std::time::Duration;

pub const DEVICE_TOKEN_HEADER: &str = "X-Device-Token";

#[derive(Debug, Clone)]
pub struct RunnerClient {
    base_url: String,
    http: Client,
}

impl RunnerClient {
    pub fn from_config(config: &AgentConfig) -> Result<Self, ApiError> {
        config.validate()?;
        let http = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .user_agent(concat!("creatingj-runner/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ApiError::Network(format!("falha ao criar cliente runner: {e}")))?;

        Ok(Self {
            base_url: config.api_base_url.trim_end_matches('/').to_owned(),
            http,
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
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

    pub async fn heartbeat(&self, device_token: &str) -> Result<DeviceSummaryResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/runner/heartbeat"))
            .header(DEVICE_TOKEN_HEADER, device_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn lease_task(&self, device_token: &str) -> Result<RunnerLeaseResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint("/api/v1/runner/tasks/lease"))
            .header(DEVICE_TOKEN_HEADER, device_token)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn post_event(
        &self,
        device_token: &str,
        task_id: &str,
        req: &RunnerTaskEventRequest,
    ) -> Result<RunnerTaskEventResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint(&format!("/api/v1/runner/tasks/{task_id}/events")))
            .header(DEVICE_TOKEN_HEADER, device_token)
            .json(req)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn request_approval(
        &self,
        device_token: &str,
        task_id: &str,
        req: &RunnerApprovalRequest,
    ) -> Result<ToolApprovalResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint(&format!("/api/v1/runner/tasks/{task_id}/approvals")))
            .header(DEVICE_TOKEN_HEADER, device_token)
            .json(req)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }

    pub async fn complete_task(
        &self,
        device_token: &str,
        task_id: &str,
        req: &RunnerCompleteTaskRequest,
    ) -> Result<RemoteTaskSummaryResponse, ApiError> {
        let resp = self
            .http
            .post(self.endpoint(&format!("/api/v1/runner/tasks/{task_id}/complete")))
            .header(DEVICE_TOKEN_HEADER, device_token)
            .json(req)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json(resp).await
    }
}
