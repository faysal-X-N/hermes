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
