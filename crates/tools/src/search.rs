use creatingj_core::CoreError;
use creatingj_workspace::Workspace;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SearchMatch {
    pub relative_path: String,
    pub line_number: usize,
    pub line_text: String,
}

pub fn search_code(
    workspace: &Workspace,
    query: &str,
    max_results: usize,
    max_file_bytes: usize,
) -> Result<Vec<SearchMatch>, CoreError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation("query de busca vazia".to_owned()));
    }
    let pattern = RegexBuilder::new(&regex::escape(trimmed))
        .case_insensitive(true)
        .size_limit(1024 * 1024)
        .build()
        .map_err(|e| CoreError::Validation(format!("padrao de busca invalido: {e}")))?;

    let files = workspace.list_files(2000)?;
    let mut results = Vec::new();
    for rel in files {
        if results.len() >= max_results {
            break;
        }
        let Ok(snapshot) = workspace.read_file_snapshot(&rel, max_file_bytes) else {
            continue;
        };
        for (idx, line) in snapshot.content.lines().enumerate() {
            if pattern.is_match(line) {
                results.push(SearchMatch {
                    relative_path: snapshot.relative_path.clone(),
                    line_number: idx + 1,
                    line_text: line.chars().take(240).collect(),
                });
                if results.len() >= max_results {
                    break;
                }
            }
        }
    }
    Ok(results)
}
