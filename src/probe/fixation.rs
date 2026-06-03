use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;

pub async fn probe_session_fixation(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = match crate::probe::common::build_probe_client(ctx.timeout_secs) {
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

    let pre_id = "fixation-test-12345";

    let resp = client
        .post(format!("{base}/mcp"))
        .header("Cookie", format!("session={pre_id}"))
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}))
        .header("Content-Type", "application/json")
        .send()
        .await;

    if let Ok(r) = resp {
        let set_cookies: Vec<String> = r.headers().get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect();

        let post_id = set_cookies.iter()
            .find_map(|c| {
                for part in c.split(';') {
                    let part = part.trim();
                    if part.to_lowercase().starts_with("session=") {
                        return Some(part.split('=').nth(1).unwrap_or("").to_string());
                    }
                }
                None
            });

        if let Some(post) = post_id {
            if pre_id == post {
                findings.push(ProbeFinding {
                    rule_id: "session-fixation".into(),
                    severity: Severity::Medium,
                    category: "session".into(),
                    title: "Session fixation — session not rotated after setting".into(),
                    target: ctx.target_url.clone(),
                    evidence: format!("Pre-set ID '{pre_id}' matched post-auth ID"),
                    recommendation: "Rotate session IDs after authentication to prevent fixation".into(),
                });
            }
        }
    }

    findings
}
