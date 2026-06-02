use super::types::BuiltinPreset;
use crate::audit::types::Severity;
use std::collections::HashMap;

pub fn dengbao_preset() -> BuiltinPreset {
    let mut rules = HashMap::new();

    let enabled_rules = vec![
        "hardcoded-api-key",
        "hardcoded-password",
        "overly-permissive",
        "no-tls",
        "no-authentication",
        "bind-public-interface",
        "auto-approve",
        "env-secret-leak",
    ];

    for rule_id in enabled_rules {
        rules.insert(rule_id.to_string(), true);
    }

    BuiltinPreset {
        name: "dengbao".into(),
        min_severity: Some(Severity::High),
        rule_state: rules,
    }
}

pub fn basic_preset() -> BuiltinPreset {
    let mut rules = HashMap::new();
    for id in &[
        "hardcoded-api-key",
        "hardcoded-password",
        "dangerous-command",
    ] {
        rules.insert(id.to_string(), true);
    }
    BuiltinPreset {
        name: "basic".into(),
        min_severity: Some(Severity::Critical),
        rule_state: rules,
    }
}

pub fn strict_preset() -> BuiltinPreset {
    let all: Vec<&str> = vec![
        "hardcoded-api-key",
        "hardcoded-password",
        "dangerous-command",
        "overly-permissive",
        "no-tls",
        "no-authentication",
        "bind-public-interface",
        "auto-approve",
        "env-secret-leak",
        "sensitive-file-args",
        "unsafe-filesystem",
        "unpinned-package",
        "supply-chain-risk",
        "no-timeout",
        "missing-description",
        "world-readable-config",
    ];
    let mut rules = HashMap::new();
    for id in &all {
        rules.insert(id.to_string(), true);
    }
    BuiltinPreset {
        name: "strict".into(),
        min_severity: Some(Severity::Low),
        rule_state: rules,
    }
}

pub fn enterprise_preset() -> BuiltinPreset {
    let mut rules = HashMap::new();
    for id in &[
        "hardcoded-api-key",
        "hardcoded-password",
        "dangerous-command",
        "overly-permissive",
        "no-tls",
        "no-authentication",
        "bind-public-interface",
        "auto-approve",
        "env-secret-leak",
        "sensitive-file-args",
        "unsafe-filesystem",
        "unpinned-package",
        "supply-chain-risk",
        "no-timeout",
        "missing-description",
        "world-readable-config",
    ] {
        rules.insert(id.to_string(), true);
    }
    BuiltinPreset {
        name: "enterprise".into(),
        min_severity: Some(Severity::Medium),
        rule_state: rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_preset_count() {
        let p = basic_preset();
        assert_eq!(p.rule_state.len(), 3);
        assert!(p.rule_state.contains_key("hardcoded-api-key"));
        assert_eq!(p.min_severity, Some(Severity::Critical));
    }

    #[test]
    fn test_dengbao_preset_count() {
        let p = dengbao_preset();
        assert_eq!(p.rule_state.len(), 8);
        assert!(p.rule_state.contains_key("no-authentication"));
    }

    #[test]
    fn test_strict_preset_count() {
        let p = strict_preset();
        assert_eq!(p.rule_state.len(), 16);
        assert_eq!(p.min_severity, Some(Severity::Low));
        assert!(p.rule_state.contains_key("world-readable-config"));
    }

    #[test]
    fn test_enterprise_preset_count() {
        let p = enterprise_preset();
        assert_eq!(p.rule_state.len(), 16);
        assert_eq!(p.min_severity, Some(Severity::Medium));
        assert!(p.rule_state.contains_key("supply-chain-risk"));
        assert!(p.rule_state.contains_key("no-timeout"));
    }
}
