use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectsPageResponse {
    pub items: Vec<ProjectResponse>,
    pub page: i32,
    pub size: i32,
    pub total_elements: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFileSnapshotRequest {
    pub relative_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAgentRunRequest {
    pub goal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default)]
    pub workspace_files: Vec<WorkspaceFileSnapshotRequest>,
    pub include_project_rag: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rag_top_k: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRunSummaryResponse {
    pub id: String,
    pub project_id: String,
    pub goal: String,
    pub model_id: Option<String>,
    pub plan_summary: Option<String>,
    pub status: String,
    pub workspace_file_count: i32,
    pub rag_match_count: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentToolProposalResponse {
    pub id: String,
    pub step_index: i32,
    pub tool_name: String,
    pub target_path: Option<String>,
    pub command_text: Option<String>,
    pub rationale: Option<String>,
    pub policy_decision: String,
    pub policy_reason: Option<String>,
    pub approval_status: String,
    pub decided_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRunDetailResponse {
    pub run: AgentRunSummaryResponse,
    #[serde(default)]
    pub proposals: Vec<AgentToolProposalResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolProposalDecisionRequest {
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolProposalDecisionResponse {
    pub run: AgentRunSummaryResponse,
    pub proposal: AgentToolProposalResponse,
}
