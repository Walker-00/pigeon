use crate::config::Security;

use super::http;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerGuess {
    pub host: String,
    pub port: u16,
    pub security: Security,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Autoconfig {
    pub imap: ServerGuess,
    pub smtp: ServerGuess,
    pub oauth: Option<crate::config::OauthProvider>,
    /// `%EMAILADDRESS%` or `%EMAILLOCALPART%` as the provider specifies it.
    pub username_is_local_part: bool,
    pub source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Builtin,
    Ispdb,
    Guessed,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Builtin => "known provider",
            Source::Ispdb => "provider database",
            Source::Guessed => "guessed from the domain",
        }
    }
}

pub fn domain_of(address: &str) -> &str {
    address
        .rsplit('@')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('>')
        .trim()
}

/// Looks up settings for an address: built-in table first (instant, and covers
/// the providers that need OAuth2), then Mozilla's ISPDB over the network, and
/// finally the conventional `imap.<domain>` / `smtp.<domain>` guess.
pub async fn discover(address: &str) -> Autoconfig {
    let domain = domain_of(address).to_ascii_lowercase();

    if let Some(c) = builtin(&domain) {
        return c;
    }
    if let Some(c) = ispdb(&domain).await {
        return c;
    }
    guess(&domain)
}

pub fn builtin(domain: &str) -> Option<Autoconfig> {
    use crate::config::OauthProvider;

    let tls = |host: &str, port: u16| ServerGuess {
        host: host.into(),
        port,
        security: Security::Tls,
    };
    let starttls = |host: &str, port: u16| ServerGuess {
        host: host.into(),
        port,
        security: Security::Starttls,
    };
    let plain = |host: &str, port: u16| ServerGuess {
        host: host.into(),
        port,
        security: Security::None,
    };

    let entry = |imap, smtp, oauth| {
        Some(Autoconfig {
            imap,
            smtp,
            oauth,
            username_is_local_part: false,
            source: Source::Builtin,
        })
    };

    match domain {
        "gmail.com" | "googlemail.com" => entry(
            tls("imap.gmail.com", 993),
            tls("smtp.gmail.com", 465),
            Some(OauthProvider::Gmail),
        ),
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" | "office365.com" => entry(
            tls("outlook.office365.com", 993),
            starttls("smtp.office365.com", 587),
            Some(OauthProvider::Outlook),
        ),
        "yahoo.com" | "yahoo.co.uk" | "ymail.com" => entry(
            tls("imap.mail.yahoo.com", 993),
            tls("smtp.mail.yahoo.com", 465),
            None,
        ),
        "fastmail.com" | "fastmail.fm" => entry(
            tls("imap.fastmail.com", 993),
            tls("smtp.fastmail.com", 465),
            None,
        ),
        "icloud.com" | "me.com" | "mac.com" => entry(
            tls("imap.mail.me.com", 993),
            starttls("smtp.mail.me.com", 587),
            None,
        ),
        // Proton and Tuta expose IMAP only through a local bridge process.
        "protonmail.com" | "proton.me" | "pm.me" => entry(
            plain("127.0.0.1", 1143),
            plain("127.0.0.1", 1025),
            None,
        ),
        "tutanota.com" | "tuta.io" => entry(plain("127.0.0.1", 1143), plain("127.0.0.1", 1025), None),
        "zoho.com" => entry(tls("imap.zoho.com", 993), tls("smtp.zoho.com", 465), None),
        "gmx.com" | "gmx.net" | "gmx.de" => entry(
            tls("imap.gmx.net", 993),
            tls("mail.gmx.net", 465),
            None,
        ),
        "web.de" => entry(tls("imap.web.de", 993), tls("smtp.web.de", 465), None),
        "mail.com" => entry(tls("imap.mail.com", 993), tls("smtp.mail.com", 465), None),
        "aol.com" => entry(
            tls("imap.aol.com", 993),
            tls("smtp.aol.com", 465),
            None,
        ),
        "yandex.com" | "yandex.ru" => entry(
            tls("imap.yandex.com", 993),
            tls("smtp.yandex.com", 465),
            None,
        ),
        "posteo.de" | "posteo.net" => entry(
            tls("posteo.de", 993),
            starttls("posteo.de", 587),
            None,
        ),
        "mailbox.org" => entry(
            tls("imap.mailbox.org", 993),
            tls("smtp.mailbox.org", 465),
            None,
        ),
        "runbox.com" => entry(tls("mail.runbox.com", 993), tls("mail.runbox.com", 465), None),
        "migadu.com" => entry(tls("imap.migadu.com", 993), tls("smtp.migadu.com", 465), None),
        "purelymail.com" => entry(
            tls("imap.purelymail.com", 993),
            tls("smtp.purelymail.com", 465),
            None,
        ),
        _ => None,
    }
}

pub fn guess(domain: &str) -> Autoconfig {
    Autoconfig {
        imap: ServerGuess {
            host: format!("imap.{domain}"),
            port: 993,
            security: Security::Tls,
        },
        smtp: ServerGuess {
            host: format!("smtp.{domain}"),
            port: 465,
            security: Security::Tls,
        },
        oauth: None,
        username_is_local_part: false,
        source: Source::Guessed,
    }
}

async fn ispdb(domain: &str) -> Option<Autoconfig> {
    let url = format!("https://autoconfig.thunderbird.net/v1.1/{domain}");
    let resp = http::get(&url).await.ok()?;
    if resp.status != 200 {
        return None;
    }
    parse_ispdb(&resp.body)
}

/// A deliberately small reader for the subset of Mozilla's autoconfig XML that
/// matters here. A full XML parser would be a large dependency for one lookup.
pub fn parse_ispdb(xml: &str) -> Option<Autoconfig> {
    let imap = parse_server(xml, "incomingServer", Some("imap"))?;
    let smtp = parse_server(xml, "outgoingServer", None)?;

    let username_is_local_part = block_of(xml, "incomingServer", Some("imap"))
        .map(|b| tag(&b, "username").is_some_and(|u| u.contains("EMAILLOCALPART")))
        .unwrap_or(false);

    Some(Autoconfig {
        imap,
        smtp,
        oauth: None,
        username_is_local_part,
        source: Source::Ispdb,
    })
}

fn block_of(xml: &str, element: &str, want_type: Option<&str>) -> Option<String> {
    let open = format!("<{element}");
    let close = format!("</{element}>");
    let mut from = 0;

    while let Some(start) = xml[from..].find(&open).map(|i| i + from) {
        let end = xml[start..].find(&close).map(|i| i + start + close.len())?;
        let block = &xml[start..end];
        let matches = match want_type {
            Some(t) => {
                let head_end = block.find('>').unwrap_or(0);
                block[..head_end].to_ascii_lowercase().contains(&format!("\"{t}\""))
            }
            None => true,
        };
        if matches {
            return Some(block.to_string());
        }
        from = end;
    }
    None
}

fn parse_server(xml: &str, element: &str, want_type: Option<&str>) -> Option<ServerGuess> {
    let block = block_of(xml, element, want_type)?;
    let host = tag(&block, "hostname")?;
    let port: u16 = tag(&block, "port")?.parse().ok()?;
    let security = match tag(&block, "socketType")?.to_ascii_uppercase().as_str() {
        "SSL" => Security::Tls,
        "STARTTLS" => Security::Starttls,
        _ => Security::None,
    };
    Some(ServerGuess { host, port, security })
}

fn tag(block: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    Some(block[start..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_providers_carry_their_oauth_setting() {
        let g = builtin("gmail.com").unwrap();
        assert_eq!(g.imap.host, "imap.gmail.com");
        assert_eq!(g.imap.port, 993);
        assert!(g.oauth.is_some());

        let p = builtin("proton.me").unwrap();
        assert_eq!(p.imap.security, Security::None);
        assert_eq!(p.imap.port, 1143);
    }

    #[test]
    fn falls_back_to_the_conventional_hostnames() {
        let g = guess("example.org");
        assert_eq!(g.imap.host, "imap.example.org");
        assert_eq!(g.smtp.host, "smtp.example.org");
        assert_eq!(g.source, Source::Guessed);
    }

    #[test]
    fn reads_mozilla_autoconfig_xml() {
        let xml = r#"
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <incomingServer type="pop3">
      <hostname>pop.example.org</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>mail.example.org</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILLOCALPART%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>send.example.org</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>"#;

        let c = parse_ispdb(xml).expect("should parse");
        assert_eq!(c.imap.host, "mail.example.org");
        assert_eq!(c.imap.security, Security::Tls);
        assert_eq!(c.smtp.host, "send.example.org");
        assert_eq!(c.smtp.port, 587);
        assert_eq!(c.smtp.security, Security::Starttls);
        assert!(c.username_is_local_part);
    }

    #[test]
    fn extracts_the_domain() {
        assert_eq!(domain_of("Ada <ada@example.org>"), "example.org");
        assert_eq!(domain_of("ada@example.org"), "example.org");
    }
}
