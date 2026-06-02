use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;

pub async fn probe_token_passthrough(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let resp = client.get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await;

    if resp.is_err() {
        findings.push(ProbeFinding {
            rule_id: "token-passthrough".into(),
            severity: Severity::Low,
            category: "permissions".into(),
            title: "Token passthrough check skipped — no OAuth metadata endpoint".into(),
            target: ctx.target_url.clone(),
            evidence: "/.well-known/oauth-authorization-server not found".into(),
            recommendation: "No action needed if OAuth is not used".into(),
        });
        return findings;
    }

    let body = resp.unwrap().text().await.unwrap_or_default();
    if !body.contains("audience") {
        findings.push(ProbeFinding {
            rule_id: "token-passthrough".into(),
            severity: Severity::Critical,
            category: "secrets".into(),
            title: "Token passthrough risk — no audience restriction in token issuance".into(),
            target: ctx.target_url.clone(),
            evidence: "OAuth metadata does not enforce token audience validation".into(),
            recommendation: "Configure token audience to prevent cross-server token passthrough".into(),
        });
    }

    findings
}

pub async fn probe_scope_minimization(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let resp = client.post(format!("{base}/mcp"))
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}))
        .header("Content-Type", "application/json")
        .send()
        .await;

    if let Ok(r) = resp {
        let json: serde_json::Value = r.json().await.unwrap_or_default();
        let scopes = json.get("result")
            .and_then(|r| r.get("scopes_supported"))
            .and_then(|s| s.as_array());

        if let Some(scopes) = scopes {
            let wildcards: Vec<&str> = scopes
                .iter()
                .filter_map(|s| s.as_str())
                .filter(|s| s.contains('*'))
                .collect();

            if !wildcards.is_empty() {
                findings.push(ProbeFinding {
                    rule_id: "scope-minimization".into(),
                    severity: Severity::Medium,
                    category: "permissions".into(),
                    title: "Overly permissive scopes — wildcard in scope definitions".into(),
                    target: ctx.target_url.clone(),
                    evidence: format!("Wildcard scopes: {}", wildcards.join(", ")),
                    recommendation: "Use explicit scope names instead of wildcards".into(),
                });
            }
        }
    }

    findings
}
