use crate::audit::types::Severity;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FuzzResult {
    pub test_id: String,
    pub tool_name: String,
    pub payload: String,
    pub severity: Severity,
    pub evidence: String,
    pub recommendation: String,
}

pub struct FuzzContext {
    pub target_url: String,
    pub timeout_secs: u64,
}

impl FuzzContext {
    pub fn new(url: &str, timeout: u64) -> Self {
        let url = if !url.starts_with("http") {
            format!("https://{url}")
        } else {
            url.to_string()
        };
        Self {
            target_url: url,
            timeout_secs: timeout,
        }
    }
}
