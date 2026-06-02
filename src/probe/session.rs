use super::types::{ProbeContext, ProbeFinding};
use crate::audit::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub async fn probe_session(ctx: &ProbeContext) -> Vec<ProbeFinding> {
    let mut findings = Vec::new();
    let base = ctx.target_url.trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(ctx.timeout_secs))
        .build()
        .unwrap();

    let mut session_ids: Vec<String> = Vec::new();
    let sample_count = 10u32;

    for i in 0..sample_count {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": i
        });

        let resp = client
            .post(format!("{base}/mcp"))
            .json(&body)
            .header("Content-Type", "application/json")
            .send()
            .await;

        match resp {
            Ok(r) => {
                let headers = r.headers();
                for value in headers.get_all("set-cookie") {
                    if let Ok(cookie) = value.to_str() {
                        for part in cookie.split(';') {
                            let part = part.trim();
                            if let Some(eq) = part.find('=') {
                                let (name, val) = part.split_at(eq);
                                if name.eq_ignore_ascii_case("session")
                                    || name.eq_ignore_ascii_case("sid")
                                    || name.eq_ignore_ascii_case("jsessionid")
                                    || name.eq_ignore_ascii_case("phpsessid")
                                {
                                    session_ids.push(val.trim_start_matches('=').to_string());
                                }
                            }
                        }
                    }
                }

                if let Some(auth_val) = headers.get("authorization") {
                    if let Ok(bearer) = auth_val.to_str() {
                        let token = bearer
                            .strip_prefix("Bearer ")
                            .unwrap_or(bearer);
                        if !token.is_empty() {
                            session_ids.push(token.to_string());
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    if session_ids.is_empty() {
        return findings;
    }

    let uuid_pattern = is_uuid(&session_ids);
    let hex_pattern = is_hex_format(&session_ids);
    let is_incremental = check_incremental(&session_ids);

    if is_incremental {
        findings.push(ProbeFinding {
            rule_id: "session-predictability".into(),
            severity: Severity::High,
            category: "session".into(),
            title: "Session IDs appear to be predictable (incrementing)".into(),
            target: ctx.target_url.clone(),
            evidence: format!(
                "Collected {} session IDs, values appear to be sequential",
                session_ids.len()
            ),
            recommendation: "Use cryptographically secure random session ID generation (e.g. UUID v4)".into(),
        });
    }

    if uuid_pattern && !is_incremental {
        findings.push(ProbeFinding {
            rule_id: "session-predictability".into(),
            severity: Severity::Low,
            category: "session".into(),
            title: "Session IDs use UUID format — good practice".into(),
            target: ctx.target_url.clone(),
            evidence: format!("{} UUID-formatted session IDs detected", session_ids.len()),
            recommendation: "No action needed".into(),
        });
    } else if hex_pattern && !is_incremental {
        findings.push(ProbeFinding {
            rule_id: "session-predictability".into(),
            severity: Severity::Low,
            category: "session".into(),
            title: "Session IDs use hex format".into(),
            target: ctx.target_url.clone(),
            evidence: format!("{} hex-formatted session IDs detected (≥128-bit recommended)", session_ids.len()),
            recommendation: "Ensure random entropy is at least 128 bits".into(),
        });
    } else if !is_incremental {
        findings.push(ProbeFinding {
            rule_id: "session-predictability".into(),
            severity: Severity::Medium,
            category: "session".into(),
            title: "Session ID format not recognized — may be predictable".into(),
            target: ctx.target_url.clone(),
            evidence: format!(
                "{} session IDs detected but format unknown (not UUID or hex)",
                session_ids.len()
            ),
            recommendation: "Use cryptographically secure session ID format (UUID v4 or 128-bit random hex)".into(),
        });
    }

    findings
}

fn is_uuid(ids: &[String]) -> bool {
    if ids.is_empty() {
        return false;
    }
    ids.iter().all(|id| {
        let id = id.trim();
        id.len() == 36
            && id.chars().nth(8) == Some('-')
            && id.chars().nth(13) == Some('-')
            && id.chars().nth(18) == Some('-')
            && id.chars().nth(23) == Some('-')
            && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    })
}

fn is_hex_format(ids: &[String]) -> bool {
    if ids.is_empty() {
        return false;
    }
    ids.iter().all(|id| {
        let id = id.trim();
        id.len() >= 32 && id.chars().all(|c| c.is_ascii_hexdigit())
    })
}

fn check_incremental(ids: &[String]) -> bool {
    if ids.len() < 2 {
        return false;
    }
    let nums: Vec<Option<u128>> = ids
        .iter()
        .map(|id| {
            let id = id.trim();
            if id.len() <= 20 {
                id.parse::<u64>().ok().map(|v| v as u128)
            } else if id.len() <= 39 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                u128::from_str_radix(id, 16).ok()
            } else {
                None
            }
        })
        .collect();

    let increasing_count = nums
        .windows(2)
        .filter(|w| match (w[0], w[1]) {
            (Some(a), Some(b)) => b > a && b - a <= 10,
            _ => false,
        })
        .count();

    increasing_count as f64 >= (ids.len() - 1) as f64 * 0.7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_uuid_valid() {
        assert!(is_uuid(&["550e8400-e29b-41d4-a716-446655440000".into()]));
    }

    #[test]
    fn test_is_uuid_invalid() {
        assert!(!is_uuid(&["not-a-uuid".into()]));
    }

    #[test]
    fn test_is_hex_format_yes() {
        assert!(is_hex_format(&["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".into()]));
    }

    #[test]
    fn test_is_hex_format_no() {
        assert!(!is_hex_format(&["xyz123".into()]));
    }

    #[test]
    fn test_check_incremental_true() {
        assert!(check_incremental(&["1".into(), "2".into(), "3".into(), "4".into()]));
    }

    #[test]
    fn test_check_incremental_false() {
        assert!(!check_incremental(&["550e8400-e29b-41d4-a716-446655440000".into(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into()]));
    }

    #[test]
    fn test_check_incremental_long_hex_not_incremental() {
        let ids: Vec<String> = vec![
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".into(),
            "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7".into(),
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".into(),
            "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7".into(),
        ];
        assert!(!check_incremental(&ids));
    }

    #[test]
    fn test_check_incremental_long_hex_sequential() {
        let ids: Vec<String> = vec![
            "00000000000000000000000000000001".into(),
            "00000000000000000000000000000002".into(),
            "00000000000000000000000000000003".into(),
            "00000000000000000000000000000004".into(),
        ];
        assert!(check_incremental(&ids));
    }
}
