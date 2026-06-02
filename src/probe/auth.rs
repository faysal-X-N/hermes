use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub async fn probe_auth(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let url = &ctx.target_url;
    let base = url.trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 1
    });

    let mcp_url = format!("{}/mcp", base);
    let response = client
        .post(&mcp_url)
        .json(&body)
        .header("Content-Type", "application/json")
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                findings.push(ProbeFinding {
                    rule_id: "auth-required".into(),
                    severity: Severity::High,
                    category: "authentication".into(),
                    title: "Server accepts unauthenticated connections".into(),
                    target: url.clone(),
                    evidence: format!("Unauthenticated request returned HTTP {}", status.as_u16()),
                    recommendation: "Enable mandatory authentication (API Key / OAuth / mTLS)".into(),
                });
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                findings.push(ProbeFinding {
                    rule_id: "auth-required".into(),
                    severity: Severity::Info,
                    category: "authentication".into(),
                    title: "Authentication OK — unauthenticated request correctly rejected".into(),
                    target: url.clone(),
                    evidence: format!("Returned HTTP {} (unauthorized)", status.as_u16()),
                    recommendation: "No action needed".into(),
                });

                let body_text = resp.text().await.unwrap_or_default();
                let leaks_details = body_text.contains("stack")
                    || body_text.contains("exception")
                    || body_text.contains("trace");
                if leaks_details {
                    findings.push(ProbeFinding {
                        rule_id: "auth-weak".into(),
                        severity: Severity::Medium,
                        category: "authentication".into(),
                        title: "Error response leaks internal details".into(),
                        target: url.clone(),
                        evidence: crate::audit::rules::safe_truncate(&body_text, 120),
                        recommendation: "Return generic error messages, avoid leaking stack traces".into(),
                    });
                }

                // PR-04: try weak token
                let weak_body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {},
                    "id": 2
                });
                let weak_response = client
                    .post(&mcp_url)
                    .json(&weak_body)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer invalid-token-12345")
                    .send()
                    .await;

                if let Ok(wr) = weak_response {
                    let ws = wr.status();
                    if ws.is_success() {
                        findings.push(ProbeFinding {
                            rule_id: "auth-weak".into(),
                            severity: Severity::Critical,
                            category: "authentication".into(),
                            title: "Server accepts weak/invalid bearer tokens".into(),
                            target: url.clone(),
                            evidence: format!("Bearer 'invalid-token-12345' returned HTTP {}", ws.as_u16()),
                            recommendation: "Validate bearer tokens properly, reject invalid tokens".into(),
                        });
                    }
                }
            }
        }
        Err(e) => {
            findings.push(ProbeFinding {
                rule_id: "auth-required".into(),
                severity: Severity::High,
                category: "authentication".into(),
                title: "Unable to connect to server — cannot verify authentication".into(),
                target: url.clone(),
                evidence: format!("Connection error: {}", e),
                recommendation: "Check that the server is running and the URL is correct".into(),
            });
        }
    }

    findings
}
