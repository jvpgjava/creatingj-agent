use regex::Regex;
use std::sync::LazyLock;

static SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let patterns = [
        r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-~+/]+=*",
        r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/]{12,}=*",
        r"(?i)(x-device-token\s*:\s*)[A-Za-z0-9._\-~+/]{8,}=*",
        r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|device[_-]?token|secret|password|passwd|token)\s*[:=]\s*['\x22]?)[^\s'\x22,;]{6,}",
        r"\b(crj_[A-Za-z0-9_\-]{12,})\b",
        r"\b(sk-[A-Za-z0-9_\-]{16,})\b",
        r"\b(ghp_[A-Za-z0-9]{20,})\b",
        r"\b(AKIA[0-9A-Z]{16})\b",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ];
    patterns
        .iter()
        .map(|p| Regex::new(p).expect("regex de redacao valido"))
        .collect()
});

pub fn redact_secrets(input: &str) -> String {
    let mut output = input.to_owned();
    for regex in SECRET_PATTERNS.iter() {
        output = regex
            .replace_all(&output, |caps: &regex::Captures<'_>| {
                if caps.len() > 1
                    && let Some(prefix) = caps.get(1)
                {
                    let full = caps.get(0).map_or("", |m| m.as_str());
                    if full.starts_with(prefix.as_str()) && prefix.as_str().len() < full.len() {
                        return format!("{}[REDACTED]", prefix.as_str());
                    }
                }
                "[REDACTED]".to_owned()
            })
            .into_owned();
    }
    output
}

pub fn contains_secret(input: &str) -> bool {
    SECRET_PATTERNS.iter().any(|regex| regex.is_match(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_bearer_device_and_provider_keys() {
        let raw = "Authorization: Bearer super_secret_token_12345 X-Device-Token: dev_tok_987654321 sk-abcdefghijklmnop123456";
        let redacted = redact_secrets(raw);
        assert!(!redacted.contains("super_secret_token_12345"));
        assert!(!redacted.contains("dev_tok_987654321"));
        assert!(!redacted.contains("sk-abcdefghijklmnop123456"));
        assert!(redacted.contains("[REDACTED]"));
        assert!(contains_secret(raw));
    }

    #[test]
    fn preserves_regular_log_messages() {
        let msg = "Executando teste unitario em crates/core com sucesso";
        assert_eq!(redact_secrets(msg), msg);
        assert!(!contains_secret(msg));
    }
}
