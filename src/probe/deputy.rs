#![allow(dead_code)]
use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;

pub async fn probe_confused_deputy(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let resp = client.post(format!("{base}/mcp"))
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}))
        .header("Content-Type", "application/json")
        .send()
        .await;

    if resp.is_err() {
        return findings;
    }

    let server_caps = resp.unwrap().text().await.unwrap_or_default();
    let has_oauth = server_caps.contains("oauth") || server_caps.contains("authorization");

    if !has_oauth {
        findings.push(ProbeFinding {
            rule_id: "confused-deputy".into(),
            severity: Severity::Low,
            category: "permissions".into(),
            title: "Confused deputy check skipped — server does not expose OAuth capabilities".into(),
            target: ctx.target_url.clone(),
            evidence: "No OAuth/authorization capability detected (protocol <2025-11-25 or not configured)".into(),
            recommendation: "Upgrade to MCP spec 2025-11-25+ and enable OAuth audience verification".into(),
        });
        return findings;
    }

    if !server_caps.contains("audience") {
        findings.push(ProbeFinding {
            rule_id: "confused-deputy".into(),
            severity: Severity::Critical,
            category: "permissions".into(),
            title: "Confused deputy risk — no audience verification configured".into(),
            target: ctx.target_url.clone(),
            evidence: "Server supports OAuth but does not enforce audience validation".into(),
            recommendation: "Enable per-client audience validation to prevent confused deputy attacks".into(),
        });
    }

    findings
}
