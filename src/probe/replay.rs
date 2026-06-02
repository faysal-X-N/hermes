#![allow(dead_code)]
use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub async fn probe_session_replay(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let mut session_id = String::new();

    for _ in 0..3 {
        let resp = client
            .post(format!("{base}/mcp"))
            .json(&serde_json::json!({"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}))
            .header("Content-Type", "application/json")
            .send()
            .await;

        if let Ok(r) = resp {
            for value in r.headers().get_all("set-cookie") {
                if let Ok(cookie) = value.to_str() {
                    for part in cookie.split(';') {
                        let part = part.trim();
                        if let Some(eq) = part.find('=') {
                            let (name, val) = part.split_at(eq);
                            if name.eq_ignore_ascii_case("session")
                                || name.eq_ignore_ascii_case("sid")
                            {
                                session_id = val.trim_start_matches('=').to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    if session_id.is_empty() {
        return findings;
    }

    let replayed = client
        .post(format!("{base}/mcp"))
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}))
        .header("Cookie", format!("session={session_id}"))
        .header("Content-Type", "application/json")
        .send()
        .await;

    match replayed {
        Ok(r) if r.status().as_u16() < 400 => {
            findings.push(ProbeFinding {
                rule_id: "session-replay".into(),
                severity: Severity::High,
                category: "session".into(),
                title: "Session replay accepted — session ID not invalidated".into(),
                target: ctx.target_url.clone(),
                evidence: "Old session ID was accepted on a new request".into(),
                recommendation: "Invalidate session IDs after use, use short-lived tokens".into(),
            });
        }
        _ => {}
    }

    findings
}
