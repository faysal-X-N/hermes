use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub async fn probe_tls(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let url = &ctx.target_url;
    let mut findings = Vec::new();

    if !url.starts_with("https://") {
        findings.push(ProbeFinding {
            rule_id: "tls-missing".into(),
            severity: Severity::High,
            category: "network".into(),
            title: "Server does not use TLS encryption".into(),
            target: url.clone(),
            evidence: "URL uses http:// protocol".into(),
            recommendation: "Enable TLS/SSL encryption for the MCP server".into(),
        });
        return findings;
    }

    let host = extract_host(url);
    let port = extract_port(url).unwrap_or(443);

    match connect_and_check_tls(&host, port, ctx.timeout_secs).await {
        Ok(tls_info) => {
            if let Some(warning) = tls_info.cert_expiry_warning {
                findings.push(ProbeFinding {
                    rule_id: "tls-verify".into(),
                    severity: Severity::Critical,
                    category: "network".into(),
                    title: "TLS certificate expired or expiring soon".into(),
                    target: url.clone(),
                    evidence: warning,
                    recommendation: "Renew the TLS certificate".into(),
                });
            }

            if let Some(weak) = tls_info.weak_cipher {
                findings.push(ProbeFinding {
                    rule_id: "tls-verify".into(),
                    severity: Severity::Medium,
                    category: "network".into(),
                    title: "Weak cipher suite negotiated".into(),
                    target: url.clone(),
                    evidence: format!("Negotiated cipher: {}", weak),
                    recommendation: "Upgrade to TLS 1.3 with strong cipher suites (AES-256-GCM, ChaCha20-Poly1305)".into(),
                });
            }

            if findings.is_empty() {
                findings.push(ProbeFinding {
                    rule_id: "tls-verify".into(),
                    severity: Severity::Info,
                    category: "network".into(),
                    title: "TLS configuration OK".into(),
                    target: url.clone(),
                    evidence: format!(
                        "TLS {} — {} — cert valid until {}",
                        tls_info.version,
                        tls_info.cipher,
                        tls_info.cert_expiry.unwrap_or_default()
                    ),
                    recommendation: "No action needed".into(),
                });
            }
        }
        Err(e) => {
            findings.push(ProbeFinding {
                rule_id: "tls-verify".into(),
                severity: Severity::Critical,
                category: "network".into(),
                title: "TLS connection failed".into(),
                target: url.clone(),
                evidence: format!("Connection failed: {}", e),
                recommendation: "Check TLS configuration and certificate validity".into(),
            });
        }
    }

    findings
}

struct TlsInfo {
    version: String,
    cipher: String,
    cert_expiry: Option<String>,
    cert_expiry_warning: Option<String>,
    weak_cipher: Option<String>,
}

async fn connect_and_check_tls(host: &str, port: u16, timeout_secs: u64) -> Result<TlsInfo, String> {
    let addr = format!("{}:{}", host, port);
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| "Connection timed out".to_string())?
        .map_err(|e| format!("TCP connection failed: {}", e))?;

    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        root_store.add(cert).ok();
    }

    let config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("Invalid hostname: {}", e))?;

    let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    let (_, conn) = tls_stream.into_inner();
    let _negotiated = conn.alpn_protocol();
    let version = conn.protocol_version().map(|v| format!("{:?}", v)).unwrap_or_else(|| "unknown".into());

    let negotiated_cs = conn.negotiated_cipher_suite();
    let cipher = negotiated_cs
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "unknown".into());

    let weak_cipher = negotiated_cs
        .and_then(|cs| {
            let suite = cs.suite();
            if suite == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                || suite == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            {
                None
            } else {
                Some(format!("{:?}", suite))
            }
        });

    let peer_certs = conn.peer_certificates();
    let (cert_expiry, cert_expiry_warning) = if let Some(certs) = peer_certs {
        if let Some(cert) = certs.first() {
            let expiry = parse_cert_expiry(cert);
            let warning = check_expiry(&expiry);
            (Some(expiry), warning)
        } else {
            (None, Some("No peer certificate provided".into()))
        }
    } else {
        (None, Some("No peer certificate provided".into()))
    };

    Ok(TlsInfo {
        version,
        cipher,
        cert_expiry,
        cert_expiry_warning,
        weak_cipher,
    })
}

fn parse_cert_expiry(cert: &rustls::pki_types::CertificateDer) -> String {
    use x509_parser::prelude::*;
    match X509Certificate::from_der(cert.as_ref()) {
        Ok((_, x509)) => x509
            .validity()
            .not_after
            .to_rfc2822()
            .unwrap_or_else(|_| "unknown".into()),
        Err(_) => "unable to parse".into(),
    }
}

fn check_expiry(expiry: &str) -> Option<String> {
    use chrono::{DateTime, Utc};
    if let Ok(dt) = DateTime::parse_from_rfc2822(expiry) {
        let now = Utc::now();
        let remaining = dt.signed_duration_since(now);
        let days = remaining.num_days();
        if days < 0 {
            Some(format!("Certificate expired {} days ago", -days))
        } else if days < 30 {
            Some(format!("Certificate expires in {} days", days))
        } else {
            None
        }
    } else {
        None
    }
}

fn extract_host(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

fn extract_port(url: &str) -> Option<u16> {
    let after_scheme = url.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    if let Some(port_str) = host_port.split(':').nth(1) {
        port_str.parse().ok()
    } else {
        None
    }
}
