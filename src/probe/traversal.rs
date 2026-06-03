use super::common::{build_probe_client, discover_fs_tools};
use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;

pub async fn probe_path_traversal(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = match build_probe_client(ctx.timeout_secs) {
        Ok(c) => c,
        Err(e) => {
            findings.push(ProbeFinding {
                rule_id: "internal-error".into(),
                severity: Severity::Critical,
                category: "internal".into(),
                title: "Failed to create HTTP client".into(),
                target: ctx.target_url.clone(),
                evidence: e,
                recommendation: "Check system network configuration".into(),
            });
            return findings;
        }
    };

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
