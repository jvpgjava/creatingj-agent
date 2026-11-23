use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateConversationRequest {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSummaryResponse {
    pub id: String,
    pub title: String,
    pub model_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationsPageResponse {
    pub items: Vec<ConversationSummaryResponse>,
    pub page: i32,
    pub size: i32,
    pub total_elements: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageResponse {
    pub id: String,
    pub role: String,
    pub content: String,
    pub sequence_num: i32,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationSummaryResponse {
    pub id: String,
    pub model_id: Option<String>,
    pub status: String,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub total_tokens: Option<i32>,
    pub error_code: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageExchangeResponse {
    pub user_message: MessageResponse,
    pub assistant_message: MessageResponse,
    pub generation: GenerationSummaryResponse,
    #[serde(default)]
    pub follow_up_suggestions: Vec<String>,
    #[serde(default)]
    pub guardrail_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationHistoryResponse {
    pub conversation: ConversationSummaryResponse,
    pub messages: Vec<MessageResponse>,
    #[serde(default)]
    pub generations: Vec<GenerationSummaryResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: String,
    pub data: String,
    pub id: Option<String>,
}
