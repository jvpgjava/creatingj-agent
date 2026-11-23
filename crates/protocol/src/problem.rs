use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProblemDetail {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub title: Option<String>,
    pub status: Option<u16>,
    pub detail: Option<String>,
    pub instance: Option<String>,
    #[serde(default)]
    pub properties: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ProblemDetail {
    pub fn error_code(&self) -> Option<&str> {
        self.properties
            .get("errorCode")
            .or_else(|| self.extra.get("errorCode"))
            .and_then(Value::as_str)
    }

    pub fn trace_id(&self) -> Option<&str> {
        self.properties
            .get("traceId")
            .or_else(|| self.extra.get("traceId"))
            .and_then(Value::as_str)
    }

    pub fn display_message(&self) -> String {
        let base = self
            .detail
            .as_deref()
            .or(self.title.as_deref())
            .unwrap_or("erro retornado pelo servidor");
        match self.error_code() {
            Some(code) => format!("[{code}] {base}"),
            None => base.to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatusResponse {
    pub service: String,
    pub api_version: String,
    pub status: String,
    pub timestamp: String,
}
