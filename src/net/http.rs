use std::collections::HashMap;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::tls::{MaybeTls, TlsError, connect_tls};

const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("HTTP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("`{0}` is not a valid https URL")]
    BadUrl(String),
    #[error("malformed HTTP response: {0}")]
    BadResponse(String),
    #[error("response body exceeded {MAX_BODY} bytes")]
    TooLarge,
    #[error("HTTP {status}: {body}")]
    Status { status: u16, body: String },
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// A deliberately small HTTPS client. It exists because every general-purpose
/// Rust HTTP client pulls in a TLS backend with a C dependency; this one reuses
/// the same rustls + graviola stack as the mail connections.
pub async fn post_form(url: &str, form: &[(&str, &str)]) -> Result<Response, HttpError> {
    let (host, port, path) = split_url(url)?;
    let body = encode_form(form);

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: pigeon/{ver}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {len}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\r\n{body}",
        ver = env!("CARGO_PKG_VERSION"),
        len = body.len(),
    );

    let stream = MaybeTls::Tls(Box::new(connect_tls(&host, port, false).await?));
    let mut io = BufReader::new(stream);
    io.get_mut().write_all(request.as_bytes()).await?;
    io.get_mut().flush().await?;

    read_response(&mut io).await
}

pub async fn get(url: &str) -> Result<Response, HttpError> {
    let (host, port, path) = split_url(url)?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: pigeon/{ver}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n",
        ver = env!("CARGO_PKG_VERSION"),
    );

    let stream = MaybeTls::Tls(Box::new(connect_tls(&host, port, false).await?));
    let mut io = BufReader::new(stream);
    io.get_mut().write_all(request.as_bytes()).await?;
    io.get_mut().flush().await?;

    read_response(&mut io).await
}

async fn read_response(io: &mut BufReader<MaybeTls>) -> Result<Response, HttpError> {
    let mut status_line = String::new();
    io.read_line(&mut status_line).await?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HttpError::BadResponse(status_line.trim().to_string()))?;

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if io.read_line(&mut line).await? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let body = match headers.get("transfer-encoding").map(|s| s.as_str()) {
        Some(te) if te.eq_ignore_ascii_case("chunked") => read_chunked(io).await?,
        _ => match headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
            Some(n) if n > MAX_BODY => return Err(HttpError::TooLarge),
            Some(n) => {
                let mut buf = vec![0u8; n];
                io.read_exact(&mut buf).await?;
                buf
            }
            None => {
                let mut buf = Vec::new();
                io.take(MAX_BODY as u64).read_to_end(&mut buf).await?;
                buf
            }
        },
    };

    Ok(Response {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

async fn read_chunked(io: &mut BufReader<MaybeTls>) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        if io.read_line(&mut size_line).await? == 0 {
            break;
        }
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
            .map_err(|_| HttpError::BadResponse(size_line.trim().to_string()))?;
        if size == 0 {
            break;
        }
        if out.len() + size > MAX_BODY {
            return Err(HttpError::TooLarge);
        }
        let mut chunk = vec![0u8; size];
        io.read_exact(&mut chunk).await?;
        out.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        io.read_exact(&mut crlf).await?;
    }
    Ok(out)
}

fn split_url(url: &str) -> Result<(String, u16, String), HttpError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| HttpError::BadUrl(url.to_string()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse().map_err(|_| HttpError::BadUrl(url.to_string()))?,
        ),
        None => (authority.to_string(), 443),
    };
    if host.is_empty() {
        return Err(HttpError::BadUrl(url.to_string()));
    }
    Ok((host, port, path.to_string()))
}

pub fn encode_form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn urlencode(s: &str) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    const UNRESERVED: &percent_encoding::AsciiSet =
        &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
    utf8_percent_encode(s, UNRESERVED).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_https_urls() {
        assert_eq!(
            split_url("https://oauth2.googleapis.com/token").unwrap(),
            ("oauth2.googleapis.com".into(), 443, "/token".into())
        );
        assert_eq!(
            split_url("https://localhost:8443").unwrap(),
            ("localhost".into(), 8443, "/".into())
        );
        assert!(split_url("http://example.org").is_err());
    }

    #[test]
    fn percent_encodes_reserved_characters() {
        assert_eq!(urlencode("a b+c/d"), "a%20b%2Bc%2Fd");
        assert_eq!(urlencode("safe-_.~"), "safe-_.~");
    }
}
