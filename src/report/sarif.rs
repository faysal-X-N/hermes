use crate::audit::types::Severity;
use serde_json::{json, Value};

pub fn build_sarif(
    path: &str,
    findings: &[crate::audit::types::Finding],
    rules: &[(&str, &str, &str)],
) -> String {
    let driver_rules: Vec<Value> = rules
        .iter()
        .map(|(id, desc, rec)| {
            json!({
                "id": id,
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": rec, "markdown": format!("**Fix:** {rec}")},
                "properties": {"category": "MCP Security"}
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let level = severity_to_sarif_level(&f.severity);

            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": &f.title},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": &f.file}
                    }
                }],
                "partialFingerprints": {
                    "ruleId": &f.rule_id,
                    "serverName": &f.server_name
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "hermes",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/faysal-X-N/hermes",
                    "rules": driver_rules
                }
            },
            "artifacts": [{
                "location": {"uri": path}
            }],
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

pub fn build_sarif_probe(
    target_url: &str,
    findings: &[crate::probe::types::ProbeFinding],
    rules: &[(&str, &str, &str)],
) -> String {
    let driver_rules: Vec<Value> = rules
        .iter()
        .map(|(id, desc, rec)| {
            json!({
                "id": id,
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": rec, "markdown": format!("**Fix:** {rec}")},
                "properties": {"category": "MCP Runtime Security"}
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let level = severity_to_sarif_level(&f.severity);

            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": &f.title},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target_url}
                    }
                }],
                "partialFingerprints": {
                    "ruleId": &f.rule_id,
                    "target": &f.target
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "hermes",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/faysal-X-N/hermes",
                    "rules": driver_rules
                }
            },
            "artifacts": [{
                "location": {"uri": target_url}
            }],
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

fn severity_to_sarif_level(severity: &Severity) -> &str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::Finding;

    fn f(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity,
            category: "test".into(),
            title: "Test finding".into(),
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
    fn test_sarif_valid_json() {
        let findings = vec![f("no-tls", Severity::Medium)];
        let rules = &[("no-tls", "No TLS detected", "Use HTTPS")];
        let json_str = build_sarif("test.json", &findings, rules);
        let sarif: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "hermes");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_sarif_levels() {
        let findings = vec![
            f("critical-rule", Severity::Critical),
            f("high-rule", Severity::High),
            f("medium-rule", Severity::Medium),
            f("low-rule", Severity::Low),
            f("info-rule", Severity::Info),
        ];
        let rules = &[];
        let json_str = build_sarif("test.json", &findings, rules);
        let sarif: Value = serde_json::from_str(&json_str).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[2]["level"], "warning");
        assert_eq!(results[3]["level"], "note");
        assert_eq!(results[4]["level"], "none");
    }

    #[test]
    fn test_sarif_empty_findings() {
        let json_str = build_sarif("test.json", &[], &[]);
        let sarif: Value = serde_json::from_str(&json_str).unwrap();
        assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
    }
}
