use super::common::discover_tools;
use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub async fn probe_ssrf_redirect(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(ctx.timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let redirect_urls = vec![
        "https://httpbin.org/redirect-to?url=http://127.0.0.1",
        "https://httpbin.org/redirect-to?url=http://localhost",
    ];

    let tools = discover_tools(&client, base).await.unwrap_or_default();

    for tool in &tools {
        for url_payload in &redirect_urls {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": tool, "arguments": { "url": url_payload } },
                "id": 1
            });

            let resp = client
                .post(format!("{base}/mcp"))
                .json(&body)
                .header("Content-Type", "application/json")
                .send()
                .await;

            if let Ok(r) = resp {
                let status = r.status().as_u16();
                if (300..400).contains(&status) {
                    if let Some(loc) = r.headers().get("location") {
                        let loc_str = loc.to_str().unwrap_or("");
                        if loc_str.contains("127.0.0.1") || loc_str.contains("localhost") || loc_str.contains("169.254") {
                            findings.push(ProbeFinding {
                                rule_id: "ssrf-redirect".into(),
                                severity: Severity::High,
                                category: "network".into(),
                                title: format!("SSRF redirect vulnerability on tool '{tool}'"),
                                target: ctx.target_url.clone(),
                                evidence: format!("Redirect to internal address: {loc_str}"),
                                recommendation: "Validate redirect targets, block internal/LAN address redirects".into(),
                            });
                        }
                    }
                }
                if status >= 500 {
                    findings.push(ProbeFinding {
                        rule_id: "ssrf-redirect".into(),
                        severity: Severity::Medium,
                        category: "network".into(),
                        title: format!("SSRF redirect probe caused server error on '{tool}'"),
                        target: ctx.target_url.clone(),
                        evidence: format!("HTTP {status}"),
                        recommendation: "Improve input validation for URL parameters".into(),
                    });
                }
            }
        }
    }

    findings
}
