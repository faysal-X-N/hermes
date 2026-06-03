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

impl Finding {
    pub fn builder() -> FindingBuilder {
        FindingBuilder::default()
    }
}

#[derive(Default)]
pub struct FindingBuilder {
    rule_id: Option<String>,
    server_name: Option<String>,
    file: Option<String>,
    severity: Option<Severity>,
    category: Option<String>,
    title: Option<String>,
    evidence: Option<String>,
    recommendation: Option<String>,
    auto_fixable: bool,
    line: Option<usize>,
    references: Vec<String>,
}

impl FindingBuilder {
    pub fn rule_id(mut self, v: &str) -> Self {
        self.rule_id = Some(v.into());
        self
    }

    pub fn server_name(mut self, v: &str) -> Self {
        self.server_name = Some(v.into());
        self
    }

    pub fn file(mut self, v: &str) -> Self {
        self.file = Some(v.into());
        self
    }

    pub fn severity(mut self, v: Severity) -> Self {
        self.severity = Some(v);
        self
    }

    pub fn category(mut self, v: &str) -> Self {
        self.category = Some(v.into());
        self
    }

    pub fn title(mut self, v: &str) -> Self {
        self.title = Some(v.into());
        self
    }

    pub fn evidence(mut self, v: &str) -> Self {
        self.evidence = Some(v.into());
        self
    }

    pub fn recommendation(mut self, v: &str) -> Self {
        self.recommendation = Some(v.into());
        self
    }

    pub fn auto_fixable(mut self, v: bool) -> Self {
        self.auto_fixable = v;
        self
    }

    pub fn build(self) -> Finding {
        Finding {
            rule_id: self.rule_id.expect("rule_id is required"),
            server_name: self.server_name.expect("server_name is required"),
            file: self.file.expect("file is required"),
            severity: self.severity.expect("severity is required"),
            category: self.category.expect("category is required"),
            title: self.title.expect("title is required"),
            evidence: self.evidence.expect("evidence is required"),
            recommendation: self.recommendation.expect("recommendation is required"),
            auto_fixable: self.auto_fixable,
            line: self.line,
            references: self.references,
        }
    }
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

pub fn score_from_counts(critical: u32, high: u32, medium: u32, low: u32) -> (u32, String) {
    let score = if 25 * critical + 10 * high + 3 * medium + low >= 100 {
        0
    } else {
        100 - 25 * critical - 10 * high - 3 * medium - low
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

    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count() as u32;

    score_from_counts(critical, high, medium, low)
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
