use crate::audit::types::Severity;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProbeFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub target: String,
    pub evidence: String,
    pub recommendation: String,
}

pub struct ProbeContext {
    pub target_url: String,
    pub timeout_secs: u64,
}

impl ProbeContext {
    pub fn new(url: &str, timeout: u64) -> Self {
        let url = if !url.starts_with("http") {
            format!("https://{}", url)
        } else {
            url.to_string()
        };
        Self {
            target_url: url,
            timeout_secs: timeout,
        }
    }
}
