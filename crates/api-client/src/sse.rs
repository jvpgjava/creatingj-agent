use crate::error::ApiError;
use creatingj_protocol::SseFrame;
use futures::StreamExt;
use reqwest::Response;

pub async fn consume_sse_stream<F>(resp: Response, mut on_frame: F) -> Result<(), ApiError>
where
    F: FnMut(SseFrame) -> Result<(), ApiError>,
{
    let mut stream = resp.bytes_stream();
    let mut raw_buf: Vec<u8> = Vec::new();
    let mut text_buf = String::new();

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(crate::map_reqwest_err)?;
        raw_buf.extend_from_slice(&chunk);

        let valid_up_to = match std::str::from_utf8(&raw_buf) {
            Ok(_) => raw_buf.len(),
            Err(err) => err.valid_up_to(),
        };

        if valid_up_to > 0 {
            let valid_str = std::str::from_utf8(&raw_buf[..valid_up_to]).map_err(|e| {
                ApiError::InvalidResponse(format!("UTF-8 invalido no stream SSE: {e}"))
            })?;
            text_buf.push_str(valid_str);
            raw_buf.drain(..valid_up_to);
        }

        while let Some((frame, consumed)) = extract_next_frame(&text_buf) {
            text_buf.drain(..consumed);
            if !frame.data.is_empty() || !frame.event.is_empty() {
                on_frame(frame)?;
            }
        }
    }

    if !raw_buf.is_empty() {
        text_buf.push_str(&String::from_utf8_lossy(&raw_buf));
    }
    if !text_buf.trim().is_empty()
        && let Some(frame) = parse_frame_block(&text_buf)
    {
        on_frame(frame)?;
    }

    Ok(())
}

fn extract_next_frame(buf: &str) -> Option<(SseFrame, usize)> {
    let lf_pos = buf.find("\n\n").map(|p| (p, 2));
    let crlf_pos = buf.find("\r\n\r\n").map(|p| (p, 4));
    let (pos, delim_len) = match (lf_pos, crlf_pos) {
        (Some(a), Some(b)) => {
            if a.0 <= b.0 {
                a
            } else {
                b
            }
        }
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };

    let block = &buf[..pos];
    let frame = parse_frame_block(block).unwrap_or(SseFrame {
        event: String::new(),
        data: String::new(),
        id: None,
    });
    Some((frame, pos + delim_len))
}

fn parse_frame_block(block: &str) -> Option<SseFrame> {
    let mut event = String::new();
    let mut data_lines = Vec::new();
    let mut id = None;

    for raw_line in block.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(val) = line.strip_prefix("event:") {
            val.trim().clone_into(&mut event);
        } else if let Some(val) = line.strip_prefix("data:") {
            data_lines.push(val.strip_prefix(' ').unwrap_or(val).to_owned());
        } else if let Some(val) = line.strip_prefix("id:") {
            id = Some(val.trim().to_owned());
        }
    }

    if event.is_empty() && data_lines.is_empty() && id.is_none() {
        return None;
    }

    Some(SseFrame {
        event: if event.is_empty() {
            "message".to_owned()
        } else {
            event
        },
        data: data_lines.join("\n"),
        id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreatingJClient, RunnerClient};
    use creatingj_core::AgentConfig;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn handles_401_429_and_sse_streaming_with_unicode() {
        let server = MockServer::start().await;
        let cfg = AgentConfig {
            api_base_url: server.uri(),
            ..AgentConfig::default()
        };
        let client = CreatingJClient::from_config(&cfg).expect("client");

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "status": 401,
                "detail": "Token expirado",
                "errorCode": "AUTH_TOKEN_EXPIRED"
            })))
            .mount(&server)
            .await;

        let err = client.me("expired").await.expect_err("401");
        assert!(matches!(err, ApiError::Unauthorized(_)));

        let sse_body = concat!(
            "event: generation.delta\n",
            "data: {\"delta\":\"Olá, \",\"generationId\":\"g1\"}\n\n",
            "event: generation.delta\n",
            "data: {\"delta\":\"ação 🚀\",\"generationId\":\"g1\"}\n\n",
            "event: generation.completed\n",
            "data: {\"generationId\":\"g1\"}\n\n"
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/conversations/c1/messages/stream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream; charset=utf-8")
                    .set_body_string(sse_body),
            )
            .mount(&server)
            .await;

        let mut frames = Vec::new();
        client
            .stream_message("tok", "c1", "oi", |f| {
                frames.push(f);
                Ok(())
            })
            .await
            .expect("stream");
        assert_eq!(frames.len(), 3);
        assert!(frames[1].data.contains("ação 🚀"));
    }

    #[tokio::test]
    async fn runner_client_sends_device_token_header() {
        let server = MockServer::start().await;
        let cfg = AgentConfig {
            api_base_url: server.uri(),
            ..AgentConfig::default()
        };
        let runner = RunnerClient::from_config(&cfg).expect("runner");

        Mock::given(method("POST"))
            .and(path("/api/v1/runner/tasks/lease"))
            .and(header("X-Device-Token", "dev-tok-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "assigned": false,
                "task": null
            })))
            .mount(&server)
            .await;

        let lease = runner.lease_task("dev-tok-1").await.expect("lease");
        assert!(!lease.assigned);
        assert!(lease.task.is_none());
    }
}
