#![allow(dead_code)]
use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub async fn probe_ssrf(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let tools = match discover_tools(&client, base).await {
        Some(t) => t,
        None => return findings,
    };

    let ssrf_payloads = vec![
        "http://127.0.0.1/",
        "http://127.0.0.1:22/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://0.0.0.0/",
    ];

    for tool in &tools {
        for url_payload in &ssrf_payloads {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": { "url": url_payload }
                },
                "id": 1
            });

            let resp = client
                .post(format!("{base}/mcp"))
                .json(&body)
                .header("Content-Type", "application/json")
                .send()
                .await;

            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status < 400 {
                        findings.push(ProbeFinding {
                            rule_id: "ssrf-probe".into(),
                            severity: Severity::Critical,
                            category: "network".into(),
                            title: format!("SSRF vulnerability detected — tool '{tool}' accepts internal URL"),
                            target: ctx.target_url.clone(),
                            evidence: format!("Payload '{url_payload}' returned HTTP {status}"),
                            recommendation: "Validate tool input URLs against allowlists, reject internal/LAN addresses".into(),
                        });
                        break;
                    }
                    if status >= 500 {
                        findings.push(ProbeFinding {
                            rule_id: "ssrf-probe".into(),
                            severity: Severity::High,
                            category: "network".into(),
                            title: format!("SSRF probe caused server error on tool '{tool}'"),
                            target: ctx.target_url.clone(),
                            evidence: format!("Payload '{url_payload}' returned HTTP {status}"),
                            recommendation: "Implement robust input validation for tool parameters".into(),
                        });
                        break;
                    }
                }
                Err(e) => {
                    if e.is_timeout() {
                        findings.push(ProbeFinding {
                            rule_id: "ssrf-probe".into(),
                            severity: Severity::High,
                            category: "network".into(),
                            title: format!("SSRF probe timed out — possible hang on tool '{tool}'"),
                            target: ctx.target_url.clone(),
                            evidence: format!("Payload '{url_payload}' caused timeout"),
                            recommendation: "Add timeout handling for tool execution".into(),
                        });
                        break;
                    }
                }
            }
        }
    }

    if findings.is_empty() && !tools.is_empty() {
        findings.push(ProbeFinding {
            rule_id: "ssrf-probe".into(),
            severity: Severity::Low,
            category: "network".into(),
            title: "No SSRF vulnerabilities detected".into(),
            target: ctx.target_url.clone(),
            evidence: "All internal URL payloads were correctly rejected".into(),
            recommendation: "No action needed".into(),
        });
    }

    findings
}

async fn discover_tools(client: &Client, base: &str) -> Option<Vec<String>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 1
    });

    let resp = client
        .post(format!("{base}/mcp"))
        .json(&body)
        .header("Content-Type", "application/json")
        .send()
        .await
        .ok()?;

    let json: serde_json::Value = resp.json().await.ok()?;
    let tools: Vec<String> = json
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if tools.is_empty() { None } else { Some(tools) }
}
