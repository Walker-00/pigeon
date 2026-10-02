use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::config::OauthProvider;
use crate::crypto::aead::random_bytes;

use super::http::{self, HttpError};

#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error("could not open a loopback listener for the OAuth redirect: {0}")]
    Listen(#[source] std::io::Error),
    #[error("the authorisation was refused: {0}")]
    Denied(String),
    #[error("the redirect did not carry an authorisation code")]
    NoCode,
    #[error("the redirect state did not match; the response may not be genuine")]
    StateMismatch,
    #[error("the provider's reply was not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the provider returned no refresh token; re-consent may be required")]
    NoRefreshToken,
    #[error("timed out waiting for the browser to complete authorisation")]
    Timeout,
    #[error("no client_id configured for this provider")]
    NoClientId,
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub scopes: &'static str,
}

pub fn endpoints(p: OauthProvider) -> Option<Endpoints> {
    Some(match p {
        OauthProvider::Gmail => Endpoints {
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            scopes: "https://mail.google.com/",
        },
        OauthProvider::Outlook => Endpoints {
            auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            scopes: "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send",
        },
        OauthProvider::Yahoo => Endpoints {
            auth_url: "https://api.login.yahoo.com/oauth2/request_auth",
            token_url: "https://api.login.yahoo.com/oauth2/get_token",
            scopes: "mail-w",
        },
        OauthProvider::Custom => return None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl Tokens {
    pub fn is_expired(&self) -> bool {
        Utc::now() + chrono::Duration::seconds(60) >= self.expires_at
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

pub struct AuthRequest {
    pub url: String,
    verifier: String,
    state: String,
    listener: TcpListener,
    redirect_uri: String,
}

/// Authorization Code flow with PKCE (RFC 7636) over a loopback redirect
/// (RFC 8252 §7.3), which is the flow Google and Microsoft require for native
/// clients and which avoids ever handling the user's password.
pub async fn begin(
    provider: OauthProvider,
    client_id: &str,
    extra_scopes: Option<&str>,
) -> Result<AuthRequest, OauthError> {
    let ep = endpoints(provider).ok_or(OauthError::NoClientId)?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(OauthError::Listen)?;
    let port = listener.local_addr().map_err(OauthError::Listen)?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/");

    let verifier = random_b64(64)?;
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_b64(24)?;
    let scopes = extra_scopes.unwrap_or(ep.scopes);

    let url = format!(
        "{}?{}",
        ep.auth_url,
        http::encode_form(&[
            ("client_id", client_id),
            ("redirect_uri", &redirect_uri),
            ("response_type", "code"),
            ("scope", scopes),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ])
    );

    Ok(AuthRequest { url, verifier, state, listener, redirect_uri })
}

impl AuthRequest {
    pub async fn wait_for_code(self, timeout: Duration) -> Result<(String, Self), OauthError> {
        let code = tokio::time::timeout(timeout, accept_redirect(&self.listener, &self.state))
            .await
            .map_err(|_| OauthError::Timeout)??;
        Ok((code, self))
    }

    pub async fn exchange(
        &self,
        provider: OauthProvider,
        client_id: &str,
        client_secret: Option<&str>,
        code: &str,
    ) -> Result<Tokens, OauthError> {
        let ep = endpoints(provider).ok_or(OauthError::NoClientId)?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", self.verifier.as_str()),
        ];
        if let Some(s) = client_secret {
            form.push(("client_secret", s));
        }
        let tokens = post_tokens(ep.token_url, &form).await?;
        if tokens.refresh_token.is_none() {
            return Err(OauthError::NoRefreshToken);
        }
        Ok(tokens)
    }
}

pub async fn refresh(
    provider: OauthProvider,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<Tokens, OauthError> {
    let ep = endpoints(provider).ok_or(OauthError::NoClientId)?;
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(s) = client_secret {
        form.push(("client_secret", s));
    }
    let mut tokens = post_tokens(ep.token_url, &form).await?;
    // Providers usually omit the refresh token on renewal; keep the old one.
    tokens.refresh_token = tokens.refresh_token.or_else(|| Some(refresh_token.to_string()));
    Ok(tokens)
}

async fn post_tokens(url: &str, form: &[(&str, &str)]) -> Result<Tokens, OauthError> {
    let resp = http::post_form(url, form).await?;
    let parsed: TokenResponse = serde_json::from_str(&resp.body)?;

    if let Some(err) = parsed.error {
        let detail = parsed.error_description.unwrap_or_default();
        return Err(OauthError::Denied(format!("{err}: {detail}")));
    }

    Ok(Tokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at: Utc::now() + chrono::Duration::seconds(parsed.expires_in.unwrap_or(3600)),
    })
}

async fn accept_redirect(listener: &TcpListener, expect_state: &str) -> Result<String, OauthError> {
    loop {
        let (stream, _) = listener.accept().await.map_err(OauthError::Listen)?;
        let mut io = BufReader::new(stream);
        let mut line = String::new();
        if io.read_line(&mut line).await.map_err(OauthError::Listen)? == 0 {
            continue;
        }

        let target = line.split_whitespace().nth(1).unwrap_or("/");
        let params = parse_query(target);

        let (body, result) = if let Some(err) = params.get("error") {
            (
                "Authorisation was refused. You can close this tab.",
                Err(OauthError::Denied(err.clone())),
            )
        } else if params.get("state").map(String::as_str) != Some(expect_state) {
            (
                "The response did not match this request. You can close this tab.",
                Err(OauthError::StateMismatch),
            )
        } else if let Some(code) = params.get("code") {
            (
                "pigeon is now authorised. You can close this tab.",
                Ok(code.clone()),
            )
        } else {
            ("No authorisation code was returned.", Err(OauthError::NoCode))
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = io.get_mut().write_all(response.as_bytes()).await;
        let _ = io.get_mut().shutdown().await;

        return result;
    }
}

fn parse_query(target: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Some(q) = target.split_once('?').map(|(_, q)| q) else { return out };
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            out.insert(urldecode(k), urldecode(v));
        }
    }
    out
}

fn urldecode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

fn random_b64(bytes: usize) -> Result<String, OauthError> {
    let mut buf = vec![0u8; bytes];
    random_bytes(&mut buf)?;
    Ok(B64URL.encode(&buf))
}

pub fn xoauth2_sasl(user: &str, access_token: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(format!("user={user}\x01auth=Bearer {access_token}\x01\x01"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redirect_query() {
        let p = parse_query("/?code=abc%2F123&state=xyz");
        assert_eq!(p.get("code").unwrap(), "abc/123");
        assert_eq!(p.get("state").unwrap(), "xyz");
    }

    #[test]
    fn builds_xoauth2_sasl_payload() {
        let s = xoauth2_sasl("a@b.c", "tok");
        let decoded = base64::engine::general_purpose::STANDARD.decode(s).unwrap();
        assert_eq!(decoded, b"user=a@b.c\x01auth=Bearer tok\x01\x01");
    }
}
