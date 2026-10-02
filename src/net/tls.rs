use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("`{0}` is not a valid DNS name or IP address")]
    BadServerName(String),
    #[error("TLS setup failed: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("could not connect to {addr}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS handshake with {host} failed: {source}")]
    Handshake {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("no trusted root certificates could be loaded")]
    NoRoots,
}

fn provider() -> &'static Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls_graviola::default_provider()))
}

/// Roots come from the system store when it has any, because corporate builds
/// and self-hosted servers depend on locally installed CAs. The bundled Mozilla
/// set is the fallback so the client still works on a bare container.
fn root_store() -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();

    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }

    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if roots.is_empty() {
        return Err(TlsError::NoRoots);
    }
    Ok(roots)
}

pub fn tls_config(accept_invalid_certs: bool) -> Result<Arc<ClientConfig>, TlsError> {
    static SAFE: OnceLock<Arc<ClientConfig>> = OnceLock::new();

    if accept_invalid_certs {
        let cfg = ClientConfig::builder_with_provider(provider().clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification(provider().clone())))
            .with_no_client_auth();
        return Ok(Arc::new(cfg));
    }

    if let Some(c) = SAFE.get() {
        return Ok(c.clone());
    }
    let cfg = ClientConfig::builder_with_provider(provider().clone())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store()?)
        .with_no_client_auth();
    Ok(SAFE.get_or_init(|| Arc::new(cfg)).clone())
}

pub async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, TlsError> {
    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect(&addr)
        .await
        .map_err(|source| TlsError::Connect { addr, source })?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

pub async fn upgrade_tls(
    stream: TcpStream,
    host: &str,
    accept_invalid_certs: bool,
) -> Result<TlsStream<TcpStream>, TlsError> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| TlsError::BadServerName(host.to_string()))?;
    let connector = TlsConnector::from(tls_config(accept_invalid_certs)?);
    connector
        .connect(name, stream)
        .await
        .map_err(|source| TlsError::Handshake { host: host.to_string(), source })
}

pub async fn connect_tls(
    host: &str,
    port: u16,
    accept_invalid_certs: bool,
) -> Result<TlsStream<TcpStream>, TlsError> {
    let tcp = connect_tcp(host, port).await?;
    upgrade_tls(tcp, host, accept_invalid_certs).await
}

#[derive(Debug)]
struct NoVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A connection that may or may not have been upgraded to TLS yet, so STARTTLS
/// flows can keep using one stream type throughout.
#[derive(Debug)]
pub enum MaybeTls {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl MaybeTls {
    pub fn is_tls(&self) -> bool {
        matches!(self, MaybeTls::Tls(_))
    }

    pub async fn upgrade(self, host: &str, accept_invalid_certs: bool) -> Result<Self, TlsError> {
        match self {
            MaybeTls::Plain(s) => Ok(MaybeTls::Tls(Box::new(
                upgrade_tls(s, host, accept_invalid_certs).await?,
            ))),
            already => Ok(already),
        }
    }
}


impl tokio::io::AsyncRead for MaybeTls {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            MaybeTls::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeTls {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            MaybeTls::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            MaybeTls::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            MaybeTls::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
