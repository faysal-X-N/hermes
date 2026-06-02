use super::types::PolicyConfig;
use std::fs;

pub fn load_policy(path: &str) -> Result<PolicyConfig, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read policy file {path}: {e}"))?;
    let policy: PolicyConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid policy JSON in {path}: {e}"))?;

    if policy.version != 1 {
        return Err(format!(
            "Unsupported policy version: {}. Only version 1 is supported",
            policy.version
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for rule_id in policy.rules.keys() {
        if !seen.insert(rule_id) {
            return Err(format!("Duplicate rule ID in policy: {rule_id}"));
        }
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_policy() {
        let json = r#"{
            "version": 1,
            "name": "Test Policy",
            "min_severity": "high",
            "rules": {
                "no-tls": { "enabled": true },
                "no-timeout": { "enabled": false }
            }
        }"#;
        let p: PolicyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(p.version, 1);
        assert!(p.is_rule_enabled("no-tls"));
        assert!(!p.is_rule_enabled("no-timeout"));
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = serde_json::from_str::<PolicyConfig>("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_version() {
        let json = r#"{
            "rules": {}
        }"#;
        let result = serde_json::from_str::<PolicyConfig>(json);
        assert!(
            result.is_err() || {
                let p = result.unwrap();
                p.version == 0
            }
        );
    }

    #[test]
    fn test_unknown_rule_defaults_to_enabled() {
        let json = r#"{
            "version": 1,
            "rules": {}
        }"#;
        let p: PolicyConfig = serde_json::from_str(json).unwrap();
        assert!(p.is_rule_enabled("some-unknown-rule"));
    }

    #[test]
    fn test_load_policy_rejects_version_2() {
        let dir = std::env::temp_dir();
        let path = dir.join("hermes_test_v2.json");
        let content = r#"{"version": 2, "rules": {}}"#;
        std::fs::write(&path, content).unwrap();
        let result = load_policy(&path.to_string_lossy());
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("version"));
    }

    #[test]
    fn test_load_policy_nonexistent_file() {
        let result = load_policy("/nonexistent/path/policy.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_policy_invalid_json_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("hermes_test_bad.json");
        std::fs::write(&path, "not valid json").unwrap();
        let result = load_policy(&path.to_string_lossy());
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err());
    }
}
