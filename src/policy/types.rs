use serde::{Deserialize, Serialize};

use crate::audit::types::Severity;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub version: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub min_severity: Option<String>,
    #[serde(default)]
    pub rules: HashMap<String, RuleEntry>,
    #[serde(default)]
    pub exceptions: Vec<Exception>,
    #[serde(skip, default)]
    pub preset_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub rule: String,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Option<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct BuiltinPreset {
    pub name: String,
    pub min_severity: Option<Severity>,
    pub rule_state: HashMap<String, bool>,
}

impl PolicyConfig {
    pub fn min_severity_value(&self) -> Option<Severity> {
        self.min_severity.as_ref().and_then(|s| parse_severity(s))
    }

    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        let entry = self.rules.get(rule_id);
        if let Some(r) = entry {
            return r.enabled;
        }
        !self.preset_mode
    }

    pub fn rule_severity_override(&self, rule_id: &str) -> Option<Severity> {
        self.rules
            .get(rule_id)
            .and_then(|r| r.severity.as_ref())
            .and_then(|s| parse_severity(s))
    }

    pub fn is_exempted(&self, rule_id: &str, tool: Option<&str>, file: &str) -> bool {
        self.exceptions.iter().any(|e| {
            if e.rule != rule_id {
                return false;
            }
            if let Some(ref tool_name) = e.tool {
                if let Some(t) = tool {
                    if t != tool_name {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(ref path) = e.path {
                if !file.contains(path) {
                    return false;
                }
            }
            if let Some(ref expiry) = e.expires {
                if let Ok(exp_date) = chrono::NaiveDate::parse_from_str(expiry, "%Y-%m-%d") {
                    let today = chrono::Utc::now().naive_utc().date();
                    if today > exp_date {
                        return false;
                    }
                }
            }
            true
        })
    }
}

pub fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

pub fn severity_to_str(s: &Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
