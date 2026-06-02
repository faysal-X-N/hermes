use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    #[serde(rename = "id")]
    pub rule_id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub file: String,
    pub server_name: String,
    pub line: Option<usize>,
    pub evidence: String,
    pub recommendation: String,
    pub auto_fixable: bool,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub target: String,
    pub findings: Vec<Finding>,
    pub summary: AuditSummary,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub files_scanned: usize,
    pub auto_fixable: usize,
    pub score: u32,
    pub grade: String,
}

pub fn compute_score(findings: &[Finding]) -> (u32, String) {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count() as u32;
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count() as u32;
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count() as u32;

    let score = if 25 * critical + 10 * high + 3 * medium >= 100 {
        0
    } else {
        100 - 25 * critical - 10 * high - 3 * medium
    };

    let grade = match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    };

    (score, grade.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(severity: Severity) -> Finding {
        Finding {
            rule_id: "test".into(),
            severity,
            category: "test".into(),
            title: "test".into(),
            file: "test.json".into(),
            server_name: "s".into(),
            line: None,
            evidence: "x".into(),
            recommendation: "y".into(),
            auto_fixable: false,
            references: Vec::new(),
        }
    }

    #[test]
    fn test_perfect_score() {
        let (score, grade) = compute_score(&[]);
        assert_eq!(score, 100);
        assert_eq!(grade, "A");
    }

    #[test]
    fn test_one_critical() {
        let findings = vec![f(Severity::Critical)];
        let (score, grade) = compute_score(&findings);
        assert_eq!(score, 75);
        assert_eq!(grade, "B");
    }

    #[test]
    fn test_two_critical() {
        let findings = vec![f(Severity::Critical), f(Severity::Critical)];
        let (score, _) = compute_score(&findings);
        assert_eq!(score, 50);
    }

    #[test]
    fn test_mixed() {
        let findings = vec![
            f(Severity::Critical),
            f(Severity::High),
            f(Severity::High),
            f(Severity::Medium),
            f(Severity::Info),
        ];
        let (score, grade) = compute_score(&findings);
        assert_eq!(score, 52); // 100 - 25 - 20 - 3
        assert_eq!(grade, "D");
    }

    #[test]
    fn test_floor_at_zero() {
        let findings = vec![
            f(Severity::Critical),
            f(Severity::Critical),
            f(Severity::Critical),
            f(Severity::Critical),
            f(Severity::Critical),
        ];
        let (score, grade) = compute_score(&findings);
        assert_eq!(score, 0);
        assert_eq!(grade, "F");
    }

    #[test]
    fn test_grade_boundaries() {
        assert_eq!(compute_score(&[]).1, "A");
        assert_eq!(compute_score(&vec![f(Severity::High)]).1, "A"); // 90
        assert_eq!(compute_score(&vec![f(Severity::Critical)]).1, "B"); // 75
        assert_eq!(
            compute_score(&vec![
                f(Severity::High),
                f(Severity::High),
                f(Severity::Medium)
            ])
            .1,
            "B"
        ); // 77
        assert_eq!(
            compute_score(&vec![f(Severity::Critical), f(Severity::High)]).1,
            "C"
        ); // 65
           // F is handled by test_floor_at_zero
    }
}
