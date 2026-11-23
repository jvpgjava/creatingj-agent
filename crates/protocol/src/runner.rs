use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePairingChallengeRequest {
    pub device_name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingChallengeResponse {
    pub challenge_id: String,
    pub pairing_code: String,
    pub device_name: String,
    pub platform: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePairingRequest {
    pub pairing_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSummaryResponse {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub status: String,
    pub online: bool,
    pub last_heartbeat_at: Option<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePairingResponse {
    pub device: DeviceSummaryResponse,
    pub device_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesResponse {
    pub items: Vec<DeviceSummaryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRemoteTaskRequest {
    pub device_id: String,
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub title: String,
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTaskSummaryResponse {
    pub id: String,
    pub project_id: String,
    pub device_id: String,
    pub title: String,
    pub instruction: String,
    pub status: String,
    pub lease_expires_at: Option<String>,
    pub result_summary: Option<String>,
    pub error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRemoteTaskResponse {
    pub task: RemoteTaskSummaryResponse,
    pub device_online: bool,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTasksResponse {
    pub items: Vec<RemoteTaskSummaryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskEventResponse {
    pub id: String,
    pub event_key: String,
    pub event_type: String,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolApprovalResponse {
    pub id: String,
    pub task_id: String,
    pub tool_name: String,
    pub target_path: Option<String>,
    pub command_text: Option<String>,
    pub diff_preview: Option<String>,
    pub status: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTaskDetailResponse {
    pub task: RemoteTaskSummaryResponse,
    #[serde(default)]
    pub events: Vec<TaskEventResponse>,
    #[serde(default)]
    pub approvals: Vec<ToolApprovalResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerLeaseResponse {
    pub assigned: bool,
    pub task: Option<RemoteTaskSummaryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerTaskEventRequest {
    pub event_key: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerTaskEventResponse {
    pub event: TaskEventResponse,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerApprovalRequest {
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolApprovalDecisionRequest {
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolApprovalDecisionResponse {
    pub task: RemoteTaskSummaryResponse,
    pub approval: ToolApprovalResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerCompleteTaskRequest {
    pub succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::problem::ProblemDetail;

    #[test]
    fn runner_lease_roundtrip_matches_backend_contract() {
        let raw = r#"{
            "assigned": true,
            "task": {
                "id": "550e8400-e29b-41d4-a716-446655440010",
                "projectId": "550e8400-e29b-41d4-a716-446655440020",
                "deviceId": "550e8400-e29b-41d4-a716-446655440030",
                "title": "Run tests",
                "instruction": "Execute cargo test",
                "status": "RUNNING",
                "leaseExpiresAt": "2026-11-22T23:00:00Z",
                "resultSummary": null,
                "errorCode": null,
                "createdAt": "2026-11-22T22:55:00Z",
                "updatedAt": "2026-11-22T22:55:00Z",
                "completedAt": null
            }
        }"#;
        let parsed: RunnerLeaseResponse = serde_json::from_str(raw).expect("parse");
        assert!(parsed.assigned);
        assert_eq!(parsed.task.expect("task").status, "RUNNING");
    }

    #[test]
    fn problem_detail_extracts_error_code_and_trace_id() {
        let raw = r#"{
            "type": "about:blank",
            "title": "Unauthorized",
            "status": 401,
            "detail": "Token expirado",
            "errorCode": "AUTH_TOKEN_EXPIRED",
            "traceId": "trace-123"
        }"#;
        let problem: ProblemDetail = serde_json::from_str(raw).expect("parse");
        assert_eq!(problem.error_code(), Some("AUTH_TOKEN_EXPIRED"));
        assert_eq!(problem.trace_id(), Some("trace-123"));
        assert_eq!(
            problem.display_message(),
            "[AUTH_TOKEN_EXPIRED] Token expirado"
        );
    }
}
