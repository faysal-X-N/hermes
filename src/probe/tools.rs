use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub struct ToolsResult {
    pub tools: Vec<String>,
    pub findings: Vec<ProbeFinding>,
}

pub async fn probe_tools(ctx: &ProbeContext) -> ToolsResult {
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
            if !resp.status().is_success() {
                findings.push(ProbeFinding {
                    rule_id: "health-check".into(),
                    severity: Severity::Info,
                    category: "authentication".into(),
                    title: "tools/list request failed — server may be down".into(),
                    target: url.clone(),
                    evidence: format!("HTTP {}", resp.status().as_u16()),
                    recommendation: "Check server authentication and permissions".into(),
                });
                return ToolsResult {
                    tools: Vec::new(),
                    findings,
                };
            }

            match resp.json::<serde_json::Value>().await {
                Ok(json) => {
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

                    findings.push(ProbeFinding {
                        rule_id: "health-check".into(),
                        severity: Severity::Info,
                        category: "authentication".into(),
                        title: format!("Server is reachable — {} tools discovered", tools.len()),
                        target: url.clone(),
                        evidence: "tools/list returned successfully".into(),
                        recommendation: "No action needed".into(),
                    });

                    findings.push(ProbeFinding {
                        rule_id: "tools-enumeration".into(),
                        severity: Severity::Info,
                        category: "authentication".into(),
                        title: format!("Found {} tools", tools.len()),
                        target: url.clone(),
                        evidence: if tools.is_empty() {
                            "No tools exposed".into()
                        } else {
                            tools.join(", ")
                        },
                        recommendation: "Periodically review exposed tool list".into(),
                    });

                    let protocol_version = json
                        .get("jsonrpc")
                        .and_then(|v| v.as_str())
                        .map(String::from);

                    if let Some(ref version) = protocol_version {
                        if version != "2.0" {
                            findings.push(ProbeFinding {
                                rule_id: "protocol-version".into(),
                                severity: Severity::Info,
                                category: "authentication".into(),
                                title: format!("MCP protocol version: {}", version),
                                target: url.clone(),
                                evidence: format!("jsonrpc: {}", version),
                                recommendation: "Upgrade to the latest MCP protocol version".into(),
                            });
                        }
                    }

                    let dangerous = find_dangerous_tools(&tools);
                    if !dangerous.is_empty() {
                        findings.push(ProbeFinding {
                            rule_id: "dangerous-tools".into(),
                            severity: Severity::High,
                            category: "permissions".into(),
                            title: format!("Found {} dangerous tools", dangerous.len()),
                            target: url.clone(),
                            evidence: dangerous.join(", "),
                            recommendation: "Restrict access to dangerous tools or add confirmation steps".into(),
                        });
                    }

                    return ToolsResult {
                        tools,
                        findings,
                    };
                }
                Err(e) => {
                    findings.push(ProbeFinding {
                        rule_id: "health-check".into(),
                        severity: Severity::High,
                        category: "authentication".into(),
                        title: "Failed to parse tools/list response".into(),
                        target: url.clone(),
                        evidence: format!("JSON parse error: {}", e),
                        recommendation: "Check that MCP protocol implementation is correct".into(),
                    });
                }
            }
        }
        Err(e) => {
            findings.push(ProbeFinding {
                rule_id: "health-check".into(),
                severity: Severity::Info,
                category: "authentication".into(),
                title: "Unable to connect to server".into(),
                target: url.clone(),
                evidence: format!("Connection error: {}", e),
                recommendation: "Check that the server is running".into(),
            });
        }
    }

    ToolsResult {
        tools: Vec::new(),
        findings,
    }
}

fn find_dangerous_tools(tools: &[String]) -> Vec<String> {
    let dangerous_prefixes = &[
        "delete", "remove", "execute", "shell", "exec",
        "bash", "run", "write", "patch", "apply", "create",
        "drop", "truncate", "sudo", "kill", "restart", "stop",
        "grant", "revoke", "admin", "root", "system",
    ];

    tools
        .iter()
        .filter(|name| {
            let lower = name.to_lowercase();
            dangerous_prefixes
                .iter()
                .any(|prefix| lower.starts_with(prefix) || lower.contains(&format!("_{}", prefix)))
        })
        .cloned()
        .collect()
}
