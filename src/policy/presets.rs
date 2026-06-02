#![allow(dead_code)]
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
    ] {
        rules.insert(id.to_string(), true);
    }
    BuiltinPreset {
        name: "enterprise".into(),
        min_severity: Some(Severity::Medium),
        rule_state: rules,
    }
}
