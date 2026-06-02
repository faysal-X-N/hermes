#![allow(dead_code)]
use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub async fn probe_path_traversal(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let tools = match discover_fs_tools(&client, base).await {
        Some(t) => t,
        None => return findings,
    };

    let traversal_payloads = vec![
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        "../../../../root/.ssh/id_rsa",
        "../../../etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ];

    for tool in &tools {
        for payload in &traversal_payloads {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": { "path": payload }
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
                            rule_id: "path-traversal".into(),
                            severity: Severity::High,
                            category: "permissions".into(),
                            title: format!("Path traversal accepted — tool '{tool}' did not reject dangerous path"),
                            target: ctx.target_url.clone(),
                            evidence: format!("Payload '{payload}' returned HTTP {status}"),
                            recommendation: "Validate file tool paths, restrict to allowed directories only".into(),
                        });
                        break;
                    }
                    if status >= 500 {
                        findings.push(ProbeFinding {
                            rule_id: "path-traversal".into(),
                            severity: Severity::Medium,
                            category: "permissions".into(),
                            title: format!("Path traversal caused server error on tool '{tool}'"),
                            target: ctx.target_url.clone(),
                            evidence: format!("Payload '{payload}' returned HTTP {status}"),
                            recommendation: "Improve input validation error handling".into(),
                        });
                        break;
                    }
                }
                Err(e) => {
                    if e.is_timeout() {
                        findings.push(ProbeFinding {
                            rule_id: "path-traversal".into(),
                            severity: Severity::Medium,
                            category: "permissions".into(),
                            title: format!("Path traversal timed out on tool '{tool}'"),
                            target: ctx.target_url.clone(),
                            evidence: format!("Payload '{payload}' caused timeout"),
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
            rule_id: "path-traversal".into(),
            severity: Severity::Low,
            category: "permissions".into(),
            title: "No path traversal vulnerabilities detected".into(),
            target: ctx.target_url.clone(),
            evidence: "All traversal payloads were correctly rejected".into(),
            recommendation: "No action needed".into(),
        });
    }

    findings
}

async fn discover_fs_tools(client: &Client, base: &str) -> Option<Vec<String>> {
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
                .filter_map(|t| {
                    let name = t.get("name").and_then(|n| n.as_str())?;
                    let lower = name.to_lowercase();
                    if lower.contains("file") || lower.contains("read") || lower.contains("write") || lower.contains("fs") {
                        Some(name.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if tools.is_empty() { None } else { Some(tools) }
}
