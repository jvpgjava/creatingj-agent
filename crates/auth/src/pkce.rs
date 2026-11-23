use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use creatingj_core::CoreError;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

#[derive(Debug, Clone)]
pub struct PkceChallenge {
    pub code_verifier: String,
    pub code_challenge: String,
    pub code_challenge_method: &'static str,
    pub state: String,
}

impl PkceChallenge {
    pub fn generate() -> Self {
        let mut verifier_bytes = [0u8; 48];
        let mut state_bytes = [0u8; 24];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut verifier_bytes);
        rng.fill_bytes(&mut state_bytes);

        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
        let state = URL_SAFE_NO_PAD.encode(state_bytes);
        let challenge_digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_digest);

        Self {
            code_verifier,
            code_challenge,
            code_challenge_method: "S256",
            state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PkceLoopbackResult {
    pub code: String,
    pub state: String,
}

pub async fn bind_loopback_listener() -> Result<(TcpListener, String), CoreError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    Ok((listener, redirect_uri))
}

pub async fn wait_for_loopback_callback(
    listener: TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<PkceLoopbackResult, CoreError> {
    let accept_result = tokio::time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| {
            CoreError::AuthRequired("tempo limite aguardando callback PKCE do navegador".to_owned())
        })?;
    let (mut stream, _) = accept_result?;

    let mut buffer = [0u8; 4096];
    let n = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    let request_line = request.lines().next().unwrap_or_default();
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let parsed = Url::parse(&format!("http://127.0.0.1{path}"))
        .map_err(|e| CoreError::AuthRequired(format!("callback PKCE invalido: {e}")))?;

    let mut code = None;
    let mut state = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }

    let (code, state) = match (code, state) {
        (Some(c), Some(s)) if s == expected_state && !c.is_empty() => (c, s),
        _ => {
            let body = "<html><body><h2>Autenticacao CreatingJ invalida</h2><p>State ou codigo ausente/invalido.</p></body></html>";
            let resp = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            return Err(CoreError::AuthRequired(
                "callback PKCE rejeitado: state divergente ou codigo ausente".to_owned(),
            ));
        }
    };

    let body = "<html><body><h2>CreatingJ autenticado!</h2><p>Voce ja pode fechar esta aba e voltar ao terminal.</p></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;

    Ok(PkceLoopbackResult { code, state })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_uses_s256_and_valid_lengths() {
        let pkce = PkceChallenge::generate();
        assert_eq!(pkce.code_challenge_method, "S256");
        assert!(pkce.code_verifier.len() >= 43);
        assert!(pkce.state.len() >= 24);
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.code_verifier.as_bytes()));
        assert_eq!(pkce.code_challenge, expected);
    }

    #[tokio::test]
    async fn loopback_callback_accepts_matching_state() {
        let (listener, redirect_uri) = bind_loopback_listener().await.expect("bind");
        let port = Url::parse(&redirect_uri)
            .expect("url")
            .port()
            .expect("port");
        let state = "state-abc-123";

        let server = tokio::spawn(async move {
            wait_for_loopback_callback(listener, state, Duration::from_secs(5)).await
        });

        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        let req = "GET /callback?code=auth_code_99&state=state-abc-123 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        client.write_all(req.as_bytes()).await.expect("write");

        let result = server.await.expect("join").expect("callback");
        assert_eq!(result.code, "auth_code_99");
        assert_eq!(result.state, "state-abc-123");
    }
}
