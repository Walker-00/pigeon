pub mod autoconfig;
pub mod http;
pub mod imap;
pub mod oauth;
pub mod smtp;
pub mod tls;

pub use tls::{MaybeTls, TlsError, connect_tcp, connect_tls, tls_config, upgrade_tls};
