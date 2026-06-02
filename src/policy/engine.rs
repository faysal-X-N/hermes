#[allow(unused_imports)]
use super::types::{BuiltinPreset, PolicyConfig};
use crate::audit::types::Finding;

pub fn apply_policy(findings: &mut Vec<Finding>, policy: &PolicyConfig) {
    findings.retain(|f| {
        if policy.is_exempted(&f.rule_id, Some(&f.server_name), &f.file) {
            return false;
        }
        if !policy.is_rule_enabled(&f.rule_id) {
            return false;
        }
        if let Some(min_sev) = policy.min_severity_value() {
            let effective = policy
                .rule_severity_override(&f.rule_id)
                .unwrap_or(f.severity);
            if effective < min_sev {
                return false;
            }
        }
        true
    });

    for f in findings.iter_mut() {
        if let Some(override_sev) = policy.rule_severity_override(&f.rule_id) {
            f.severity = override_sev;
        }
    }
}

#[cfg(test)]
pub fn apply_preset(findings: &mut Vec<Finding>, preset: &BuiltinPreset) {
    findings.retain(|f| {
        let enabled = preset.rule_state.get(&f.rule_id).copied().unwrap_or(false);
        if !enabled {
            return false;
        }
        if let Some(min_sev) = &preset.min_severity {
            if f.severity < *min_sev {
                return false;
            }
        }
        true
    });
}

#[cfg(test)]
mod tests {
    use super::super::types::PolicyConfig;
    use super::*;
    use crate::audit::types::{Finding, Severity};

    fn make_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity,
            category: "test".into(),
            title: "Test".into(),
            file: "test.json".into(),
            server_name: "test".into(),
            line: None,
            evidence: "test".into(),
            recommendation: "fix".into(),
            auto_fixable: false,
            references: Vec::new(),
        }
    }

    #[test]
    fn test_policy_filter_rule_disabled() {
        let policy: PolicyConfig = serde_json::from_str(
            r#"{
            "version": 1,
            "rules": { "no-tls": { "enabled": false } }
        }"#,
        )
        .unwrap();
        let mut findings = vec![
            make_finding("no-tls", Severity::Medium),
            make_finding("auto-approve", Severity::High),
        ];
        apply_policy(&mut findings, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "auto-approve");
    }

    #[test]
    fn test_policy_filter_min_severity() {
        let policy: PolicyConfig = serde_json::from_str(
            r#"{
            "version": 1,
            "min_severity": "high",
            "rules": {}
        }"#,
        )
        .unwrap();
        let mut findings = vec![
            make_finding("no-tls", Severity::Medium),
            make_finding("auto-approve", Severity::High),
            make_finding("no-timeout", Severity::Low),
        ];
        apply_policy(&mut findings, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "auto-approve");
    }

    #[test]
    fn test_dengbao_preset() {
        let preset = super::super::presets::dengbao_preset();
        let mut findings = vec![
            make_finding("hardcoded-api-key", Severity::Critical),
            make_finding("no-tls", Severity::Medium),
            make_finding("unknown-rule", Severity::High),
        ];
        apply_preset(&mut findings, &preset);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "hardcoded-api-key");
    }

    #[test]
    fn test_exemption_by_rule() {
        let policy: PolicyConfig = serde_json::from_str(
            r#"{
            "version": 1,
            "exceptions": [{"rule": "no-tls", "reason": "test env"}]
        }"#,
        )
        .unwrap();
        let mut findings = vec![
            make_finding("no-tls", Severity::Medium),
            make_finding("auto-approve", Severity::High),
        ];
        apply_policy(&mut findings, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "auto-approve");
    }

    #[test]
    fn test_exemption_expired() {
        let policy: PolicyConfig = serde_json::from_str(
            r#"{
            "version": 1,
            "exceptions": [{"rule": "no-tls", "reason": "test", "expires": "2020-01-01"}]
        }"#,
        )
        .unwrap();
        let mut findings = vec![make_finding("no-tls", Severity::Medium)];
        apply_policy(&mut findings, &policy);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_exemption_by_tool() {
        let policy: PolicyConfig = serde_json::from_str(
            r#"{
            "version": 1,
            "exceptions": [{"rule": "dangerous-tools", "tool": "write_file", "reason": "allowed"}]
        }"#,
        )
        .unwrap();
        assert!(policy.is_exempted("dangerous-tools", Some("write_file"), "test.json"));
        assert!(!policy.is_exempted("dangerous-tools", Some("execute"), "test.json"));
    }
}
