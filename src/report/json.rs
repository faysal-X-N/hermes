use crate::audit::types::{compute_score, AuditReport, AuditSummary, Finding, Severity};
use chrono::Utc;

pub fn build_audit_json(
    target: &str,
    findings: &[Finding],
    files_scanned: usize,
    duration_ms: u64,
    auto_fixable: usize,
) -> AuditReport {
    let (score, grade) = compute_score(findings);

    let critical = count(findings, &Severity::Critical);
    let high = count(findings, &Severity::High);
    let medium = count(findings, &Severity::Medium);
    let low = count(findings, &Severity::Low);
    let info = count(findings, &Severity::Info);

    AuditReport {
        target: target.into(),
        findings: findings.to_vec(),
        summary: AuditSummary {
            total: findings.len(),
            critical,
            high,
            medium,
            low,
            info,
            files_scanned,
            auto_fixable,
            score,
            grade,
        },
        duration_ms,
    }
}

pub fn to_json(report: &AuditReport) -> String {
    let mut output = serde_json::json!({
        "tool": "hermes",
        "version": env!("CARGO_PKG_VERSION"),
        "command": "audit",
        "timestamp": Utc::now().to_rfc3339(),
        "target": report.target,
    });

    let (score, grade) = compute_score(&report.findings);
    output["score"] = serde_json::json!({
        "grade": grade,
        "numeric": score,
        "breakdown": {
            "secrets": sub_score(&report.findings, "secrets"),
            "permissions": sub_score(&report.findings, "permissions"),
            "network": sub_score(&report.findings, "network"),
            "authentication": sub_score(&report.findings, "authentication"),
            "session": sub_score(&report.findings, "session"),
        }
    });

    output["summary"] = serde_json::json!({
        "total": report.summary.total,
        "critical": report.summary.critical,
        "high": report.summary.high,
        "medium": report.summary.medium,
        "low": report.summary.low,
        "info": report.summary.info,
        "files_scanned": report.summary.files_scanned,
        "auto_fixable": report.summary.auto_fixable,
        "duration_ms": report.duration_ms,
    });

    output["findings"] = serde_json::to_value(&report.findings).unwrap();

    serde_json::to_string_pretty(&output).unwrap()
}

fn sub_score(findings: &[Finding], category: &str) -> u32 {
    let cat_findings: Vec<Finding> = findings
        .iter()
        .filter(|f| f.category == category)
        .cloned()
        .collect();
    let (score, _) = compute_score(&cat_findings);
    score
}

fn count(findings: &[Finding], severity: &Severity) -> usize {
    findings.iter().filter(|f| &f.severity == severity).count()
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
            title: "T".into(),
            file: "x".into(),
            server_name: "s".into(),
            line: None,
            evidence: "e".into(),
            recommendation: "r".into(),
            auto_fixable: false,
            references: Vec::new(),
        }
    }

    #[test]
    fn test_build_audit_json_has_required_fields() {
        let findings = vec![f("no-tls", Severity::Medium)];
        let report = build_audit_json("test.json", &findings, 1, 50, 1);
        assert_eq!(report.target, "test.json");
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_to_json_produces_valid_json() {
        let findings = vec![f("no-tls", Severity::Medium)];
        let report = build_audit_json("test.json", &findings, 1, 50, 1);
        let json = to_json(&report);
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }
}
