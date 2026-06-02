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
