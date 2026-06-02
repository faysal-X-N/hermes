#![allow(dead_code)]
use crate::audit::types::{Finding, Severity};
use console::{style, Color};

#[derive(Clone)]
pub struct ScanStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub duration_ms: u64,
    pub items_scanned: String,
    pub files_scanned: usize,
}

impl ScanStats {
    pub fn from_counts(
        total: usize,
        critical: usize,
        high: usize,
        medium: usize,
        low: usize,
        info: usize,
        duration_ms: u64,
    ) -> Self {
        Self {
            total,
            critical,
            high,
            medium,
            low,
            info,
            duration_ms,
            items_scanned: String::new(),
            files_scanned: 0,
        }
    }
}

pub fn print_header(title: &str, command: &str) {
    println!(
        "{} {} {}",
        style("===").dim(),
        style("Hermes").bold().cyan(),
        style(format!("{command} Report")).bold().cyan()
    );
    println!("  {}  {}", style("Target:").dim(), title);
    println!();
}

pub fn print_score(score: u32, grade: &str) {
    let (score_color, _grade_color) = match grade {
        "A" | "B" => (Color::Green, Color::Green),
        "C" => (Color::Yellow, Color::Yellow),
        _ => (Color::Red, Color::Red),
    };
    println!(
        "  {}  {}/{}  {}",
        style("Score:").dim(),
        style(score).fg(score_color).bold(),
        style("100").dim(),
        style(format!("({grade})")).bold(),
    );
}

pub fn print_summary_no_score(stats: &ScanStats) {
    println!(
        "  {}  {} total ({} {}  {} {}  {} {}  {} {}  {} {})",
        style("Findings:").dim(),
        style(stats.total).bold(),
        style(stats.critical).red().bold(),
        style("critical").red(),
        style(stats.high).yellow().bold(),
        style("high").yellow(),
        style(stats.medium).blue().bold(),
        style("medium").blue(),
        style(stats.low).dim().bold(),
        style("low").dim(),
        style(stats.info).green().bold(),
        style("info").green(),
    );
    if !stats.items_scanned.is_empty() {
        println!("  {}  {}", style("Items:").dim(), stats.items_scanned);
    }
    println!("  {}  {}ms", style("Duration:").dim(), stats.duration_ms);
    println!();
}

pub fn print_audit_summary(stats: &ScanStats) {
    let mut s = stats.clone();
    s.items_scanned = format!("{} files", stats.files_scanned);
    print_summary_no_score(&s);
}

pub fn print_probe_summary(stats: &ScanStats) {
    print_summary_no_score(stats);
}

pub fn print_audit_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("  {}", style("No issues found.").green());
        return;
    }

    for finding in findings {
        print_finding_line(
            &finding.rule_id,
            &finding.title,
            &finding.server_name,
            &finding.severity,
            &finding.evidence,
            &finding.recommendation,
        );
        println!("    {}  {}", style("File:").dim(), finding.file);
        if let Some(line) = finding.line {
            println!("    {}  {}", style("Line:").dim(), line);
        }
        if finding.auto_fixable {
            println!(
                "    {}  {}",
                style("Auto-fix:").dim(),
                style("auto-fixable with --fix").green()
            );
        }
        println!();
    }
}

pub fn print_probe_findings(
    findings: &[super::super::probe::types::ProbeFinding],
    tools: &[String],
) {
    if !tools.is_empty() {
        println!("  {} ({}):", style("Tools discovered").bold(), tools.len());
        for tool in tools {
            println!("    - {tool}");
        }
        println!();
    }

    if findings.is_empty() {
        println!("  {}", style("No issues found.").green());
        return;
    }

    for finding in findings {
        print_finding_line(
            &finding.rule_id,
            &finding.title,
            &finding.target,
            &finding.severity,
            &finding.evidence,
            &finding.recommendation,
        );
        println!();
    }
}

fn print_finding_line(
    rule_id: &str,
    title: &str,
    target: &str,
    severity: &Severity,
    evidence: &str,
    recommendation: &str,
) {
    let sev_style = match severity {
        Severity::Critical => style("CRITICAL").red().bold(),
        Severity::High => style("HIGH").yellow().bold(),
        Severity::Medium => style("MEDIUM").blue().bold(),
        Severity::Low => style("LOW").dim().bold(),
        Severity::Info => style("INFO").green().bold(),
    };

    println!(
        "  [{}] {} - {} ({})",
        sev_style,
        style(rule_id).bold(),
        title,
        style(target).cyan(),
    );
    println!("    {}  {}", style("Evidence:").dim(), evidence);
    println!("    {}  {}", style("Fix:").dim(), recommendation);
}

pub fn build_audit_report(
    path: &str,
    score: u32,
    grade: &str,
    stats: &ScanStats,
    findings: &[Finding],
) -> String {
    use std::fmt::Write;
    let mut buf = String::new();
    writeln!(buf, "=== Hermes Audit Report").ok();
    writeln!(buf, "  Target:  {path}").ok();
    writeln!(buf).ok();
    writeln!(buf, "  Score:  {score}/100  ({grade})").ok();
    writeln!(
        buf,
        "  Findings:  {total} total ({critical} critical  {high} high  {medium} medium  {low} low  {info} info)",
        total = stats.total, critical = stats.critical, high = stats.high, medium = stats.medium, low = stats.low, info = stats.info
    )
    .ok();
    writeln!(buf, "  Items:  {} files", stats.files_scanned).ok();
    writeln!(buf, "  Duration:  {}ms", stats.duration_ms).ok();
    writeln!(buf).ok();
    for f in findings {
        let sev = match f.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        writeln!(
            buf,
            "  [{}] {} - {} ({})",
            sev, f.rule_id, f.title, f.server_name
        )
        .ok();
        writeln!(buf, "    Evidence:  {}", f.evidence).ok();
        writeln!(buf, "    Fix:  {}", f.recommendation).ok();
        writeln!(buf, "    File:  {}", f.file).ok();
        if let Some(line) = f.line {
            writeln!(buf, "    Line:  {line}").ok();
        }
        if f.auto_fixable {
            writeln!(buf, "    Auto-fix:  auto-fixable with --fix").ok();
        }
        writeln!(buf).ok();
    }
    buf
}

pub fn build_probe_report(
    target: &str,
    stats: &ScanStats,
    findings: &[super::super::probe::types::ProbeFinding],
    tools: &[String],
) -> String {
    use std::fmt::Write;
    let mut buf = String::new();
    writeln!(buf, "=== Hermes Probe Report").ok();
    writeln!(buf, "  Target:  {target}").ok();
    writeln!(buf).ok();
    writeln!(
        buf,
        "  Findings:  {total} total ({critical} critical  {high} high  {medium} medium  {low} low  {info} info)",
        total = stats.total, critical = stats.critical, high = stats.high, medium = stats.medium, low = stats.low, info = stats.info
    )
    .ok();
    writeln!(buf, "  Duration:  {}ms", stats.duration_ms).ok();
    writeln!(buf).ok();
    if !tools.is_empty() {
        writeln!(buf, "  Tools discovered ({}):", tools.len()).ok();
        for tool in tools {
            writeln!(buf, "    - {tool}").ok();
        }
        writeln!(buf).ok();
    }
    for f in findings {
        let sev = match f.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        writeln!(buf, "  [{}] {} - {}", sev, f.rule_id, f.title).ok();
        writeln!(buf, "    Evidence:  {}", f.evidence).ok();
        writeln!(buf, "    Fix:  {}", f.recommendation).ok();
        writeln!(buf).ok();
    }
    buf
}
