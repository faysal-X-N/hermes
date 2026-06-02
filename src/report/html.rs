#![allow(dead_code)]
use crate::audit::types::{Finding, Severity};

pub fn build_html_audit(path: &str, findings: &[Finding], score: u32, grade: &str) -> String {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let finding_rows: String = findings
        .iter()
        .map(|f| {
            let sev = format!("{:?}", f.severity).to_lowercase();
            let css_class = match f.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                _ => "info",
            };
            format!(
                "<tr class=\"{css_class}\"><td>{sev}</td><td>{rule}</td><td>{title}</td><td>{file}</td><td>{evidence}</td><td>{rec}</td></tr>",
                rule = f.rule_id,
                title = f.title,
                file = f.file,
                evidence = f.evidence,
                rec = f.recommendation,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Hermes Audit Report — {path}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:40px;background:#111;color:#eee}}
h1{{color:#fff;border-bottom:2px solid #333;padding-bottom:8px}}
.score{{font-size:64px;font-weight:bold;margin:0}}
.grade{{font-size:28px;margin-left:12px}}
.critical{{color:#ff4444}} .high{{color:#ffaa00}} .medium{{color:#4499ff}} .low{{color:#888}} .info{{color:#44cc44}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #333}}
th{{background:#222}} tr:hover{{background:#1a1a1a}}
.summary{{display:flex;gap:24px;margin:16px 0}}
.stat{{text-align:center}} .stat .num{{font-size:24px;font-weight:bold}}
</style>
</head>
<body>
<h1>Hermes Audit Report</h1>
<p>Target: <code>{path}</code></p>
<div class="summary">
<div class="stat"><div class="num score">{score}</div><div>Score</div></div>
<div class="stat"><div class="num grade">{grade}</div><div>Grade</div></div>
<div class="stat critical"><div class="num">{critical}</div><div>Critical</div></div>
<div class="stat high"><div class="num">{high}</div><div>High</div></div>
<div class="stat medium"><div class="num">{medium}</div><div>Medium</div></div>
<div class="stat low"><div class="num">{low}</div><div>Low</div></div>
<div class="stat info"><div class="num">{info}</div><div>Info</div></div>
</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>File</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{finding_rows}</tbody></table>
</body></html>"#
    )
}

pub fn build_html_probe(target: &str, findings: &[crate::probe::types::ProbeFinding]) -> String {
    let finding_rows: String = findings
        .iter()
        .map(|f| {
            let sev = format!("{:?}", f.severity).to_lowercase();
            format!(
                "<tr><td>{sev}</td><td>{rule}</td><td>{title}</td><td>{evidence}</td><td>{rec}</td></tr>",
                rule = f.rule_id,
                title = f.title,
                evidence = f.evidence,
                rec = f.recommendation,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Hermes Probe Report — {target}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:40px;background:#111;color:#eee}}
h1{{color:#fff;border-bottom:2px solid #333;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #333}}
th{{background:#222}} tr:hover{{background:#1a1a1a}}
</style>
</head>
<body>
<h1>Hermes Probe Report</h1>
<p>Target: <code>{target}</code></p>
<p>Findings: {count}</p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{finding_rows}</tbody></table>
</body></html>"#,
        count = findings.len(),
    )
}
