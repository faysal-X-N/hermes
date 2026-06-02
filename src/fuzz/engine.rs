use super::payloads;
use super::types::{FuzzContext, FuzzResult};
use crate::audit::types::Severity;
use crate::probe::common::discover_tools;
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

pub async fn run_fuzz(ctx: &FuzzContext, test_ids: &[&str]) -> Vec<FuzzResult> {
    let mut results = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let tools = match discover_tools(&client, base).await {
        Some(t) => t,
        None => {
            results.push(FuzzResult {
                test_id: "health-check".into(),
                tool_name: "—".into(),
                payload: "—".into(),
                severity: Severity::Info,
                evidence: "Could not discover tools — server may be down".into(),
                recommendation: "Check that the server is running".into(),
            });
            return results;
        }
    };

    for test_id in test_ids {
        match *test_id {
            "FZ-01" => {
                for payload in payloads::empty_payloads() {
                    for tool in &tools {
                        let result = fuzz_tool(&client, base, test_id, tool, &payload).await;
                        results.push(result);
                    }
                }
            }
            "FZ-02" => {
                for payload in payloads::oversized_payloads() {
                    for tool in &tools {
                        let result = fuzz_tool(&client, base, test_id, tool, &payload).await;
                        results.push(result);
                    }
                }
            }
            "FZ-03" => {
                for payload in payloads::special_char_payloads() {
                    for tool in &tools {
                        let result = fuzz_tool(&client, base, test_id, tool, &payload).await;
                        results.push(result);
                    }
                }
            }
            "FZ-04" => {
                for payload in payloads::path_injection_payloads() {
                    for tool in &tools {
                        let result = fuzz_tool(&client, base, test_id, tool, &payload).await;
                        results.push(result);
                    }
                }
            }
            "FZ-05" => {
                for payload in payloads::sql_injection_payloads() {
                    for tool in &tools {
                        let result = fuzz_tool(&client, base, test_id, tool, &payload).await;
                        results.push(result);
                    }
                }
            }
            "FZ-06" => {
                for payload in payloads::command_injection_payloads() {
                    for tool in &tools {
                        let result = fuzz_tool(&client, base, test_id, tool, &payload).await;
                        results.push(result);
                    }
                }
            }
            "FZ-07" => {
                for payload in payloads::prompt_injection_payloads() {
                    for tool in &tools {
                        let result = fuzz_tool(&client, base, test_id, tool, &payload).await;
                        results.push(result);
                    }
                }
            }
            _ => {
                results.push(FuzzResult {
                    test_id: test_id.to_string(),
                    tool_name: "—".into(),
                    payload: "—".into(),
                    severity: Severity::Info,
                    evidence: format!("Test {test_id} not yet implemented"),
                    recommendation: "—".into(),
                });
            }
        }
    }

    results
}

async fn fuzz_tool(
    client: &Client,
    base: &str,
    test_id: &str,
    tool_name: &str,
    payload: &Value,
) -> FuzzResult {
    let payload_display = truncate(&serde_json::to_string(payload).unwrap_or_default(), 60);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": payload
        },
        "id": 1
    });

    let response = client
        .post(format!("{base}/mcp"))
        .json(&body)
        .header("Content-Type", "application/json")
        .send()
        .await;

    let (severity, evidence, recommendation) = match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status >= 500 {
                (
                    Severity::High,
                    format!("Server returned HTTP {status} — possible crash"),
                    "Implement input validation for empty/null parameters",
                )
            } else if status >= 400 {
                (
                    Severity::Info,
                    format!("Server rejected input with HTTP {status} — expected behavior"),
                    "No action needed",
                )
            } else {
                let body_text = resp.text().await.unwrap_or_default();
                if body_text.to_lowercase().contains("error") {
                    (
                        Severity::Low,
                        format!("Server returned success but body contains error: {}",
                            truncate(&body_text, 100)),
                        "Ensure error handling is robust and does not leak information",
                    )
                } else {
                    (
                        Severity::Medium,
                        "Server accepted empty/null input without error \u{2014} potential robustness gap"
                        .to_string(),
                        "Consider adding input validation for empty/null parameters",
                    )
                }
            }
        }
        Err(e) => {
            let is_timeout = e.is_timeout();
            if is_timeout {
                (
                    Severity::High,
                    "Connection timed out — server may have crashed or hung".into(),
                    "Check server resilience to empty/null inputs",
                )
            } else {
                (
                    Severity::High,
                    format!("Connection error: {e}"),
                    "Server may have crashed on empty/null input",
                )
            }
        }
    };

    FuzzResult {
        test_id: test_id.to_string(),
        tool_name: tool_name.to_string(),
        payload: payload_display,
        severity,
        evidence,
        recommendation: recommendation.into(),
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}
