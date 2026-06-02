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

pub fn build_html_management(
    path: &str,
    findings: &[Finding],
    score: u32,
    grade: &str,
    files_scanned: usize,
    duration_ms: u64,
) -> String {
    let sevs = vec![
        (
            "critical",
            "Critical",
            "#ff4444",
            findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
        ),
        (
            "high",
            "High",
            "#ffaa00",
            findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
        ),
        (
            "medium",
            "Medium",
            "#4499ff",
            findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
        ),
        (
            "low",
            "Low",
            "#888888",
            findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
        ),
        (
            "info",
            "Info",
            "#44cc44",
            findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
        ),
    ];

    let total = findings.len();
    let max_count = sevs.iter().map(|(_, _, _, c)| *c).max().unwrap_or(1).max(1);

    let bars: String = sevs.iter().map(|(label, _name, color, count)| {
        let pct = if total > 0 { *count as f64 / total as f64 * 100.0 } else { 0.0 };
        let width = if max_count > 0 { *count as f64 / max_count as f64 * 100.0 } else { 0.0 };
        format!(r#"<div class="bar-row"><span class="bar-label">{label}</span><div class="bar-track"><div class="bar-fill" style="width:{width}%;background:{color}"></div></div><span class="bar-num">{count} ({pct:.0}%)</span></div>"#)
    }).collect::<Vec<_>>().join("\n");

    let cat_counts: std::collections::HashMap<&str, usize> =
        findings
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, f| {
                *acc.entry(&f.category).or_default() += 1;
                acc
            });

    let cat_bars: String = cat_counts.iter().map(|(cat, count)| {
        let pct = if total > 0 { *count as f64 / total as f64 * 100.0 } else { 0.0 };
        format!(r#"<div class="bar-row"><span class="bar-label">{cat}</span><div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:#666"></div></div><span class="bar-num">{count} ({pct:.0}%)</span></div>"#)
    }).collect::<Vec<_>>().join("\n");

    let grade_color = match grade {
        "A" => "#44cc44",
        "B" => "#88cc44",
        "C" => "#ccaa44",
        "D" => "#cc6644",
        _ => "#ff4444",
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Hermes Management Report — {path}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:40px;background:#fff;color:#222}}
h1{{border-bottom:3px solid #4a90d9;padding-bottom:12px;color:#333}}
h2{{color:#555;margin-top:32px}}
.score-card{{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;border-radius:12px;padding:32px;display:flex;align-items:center;gap:32px;margin:16px 0}}
.score-num{{font-size:80px;font-weight:700;color:{grade_color}}}
.score-grade{{font-size:48px;font-weight:300;color:#aaa}}
.meta{{color:#aaa;font-size:14px;margin-top:8px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin:16px 0}}
.stat-card{{background:#f5f5f5;border-radius:8px;padding:16px;text-align:center;border-left:4px solid}}
.stat-card .num{{font-size:28px;font-weight:bold}}
.stat-card .lbl{{font-size:13px;color:#666;text-transform:uppercase;margin-top:4px}}
.bar-row{{display:flex;align-items:center;gap:12px;margin:8px 0}}
.bar-label{{width:80px;text-align:right;font-size:13px;color:#555}}
.bar-track{{flex:1;height:20px;background:#eee;border-radius:10px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:10px;transition:width 0.5s}}
.bar-num{{width:80px;font-size:13px;color:#888}}
table{{width:100%;border-collapse:collapse;margin:16px 0}}
th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #ddd}}
th{{background:#f0f0f0;font-weight:600}}
.dengbao-table td:first-child{{font-weight:500}}
.pass{{color:#44cc44}} .fail{{color:#ff4444}} .warn{{color:#ccaa44}}
footer{{margin-top:40px;padding-top:16px;border-top:1px solid #ddd;color:#999;font-size:12px}}
</style>
</head>
<body>
<h1>MCP Security Management Report</h1>
<div class="meta">Target: <code>{path}</code> &bull; Files: {files_scanned} &bull; Duration: {duration_ms}ms</div>

<div class="score-card">
<div class="score-num">{score}</div>
<div><div class="score-grade">Grade {grade}</div><div style="color:#888;font-size:14px">Composite Security Score</div></div>
</div>

<div class="grid">
{sev_card}
</div>

<h2>Severity Distribution</h2>
{bars}

<h2>Category Breakdown</h2>
{cat_bars}

<h2>Dengbao 2.0 Level 2 Compliance</h2>
{dengbao_table}

<h2>Top Findings</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Recommendation</th></tr></thead>
<tbody>{top_rows}</tbody></table>

<footer>Generated by Hermes v{ver} &bull; <a href="https://github.com/faysal-X-N/hermes">github.com/faysal-X-N/hermes</a></footer>
</body></html>"#,
        sev_card = sevs.iter().map(|(_, name, color, count)| format!(r#"<div class="stat-card" style="border-color:{color}"><div class="num" style="color:{color}">{count}</div><div class="lbl">{name}</div></div>"#)).collect::<Vec<_>>().join("\n"),
        dengbao_table = build_dengbao_table(findings),
        top_rows = build_top_findings(findings),
        ver = env!("CARGO_PKG_VERSION"),
    )
}

fn build_dengbao_table(findings: &[Finding]) -> String {
    let check = |ids: &[&str]| -> (&str, String) {
        let count = findings
            .iter()
            .filter(|f| ids.contains(&f.rule_id.as_str()))
            .count();
        if count == 0 {
            ("PASS", String::new())
        } else {
            ("FAIL", format!("{count} issues"))
        }
    };
    let rows: Vec<(&str, &str, &[&str])> = vec![
        (
            "访问控制",
            "SC-01/04/06/08",
            &[
                "hardcoded-api-key",
                "overly-permissive",
                "no-authentication",
                "auto-approve",
            ],
        ),
        (
            "安全审计",
            "SC-02/11",
            &["hardcoded-password", "env-secret-leak"],
        ),
        ("通信完整性", "SC-05", &["no-tls"]),
        ("通信保密性", "SC-05", &["no-tls"]),
        ("软件容错", "FZ-01/08", &[]),
        ("网络安全", "SC-07", &["bind-public-interface"]),
    ];
    let rows_html: String = rows.iter().map(|(req, rules, ids)| {
        let (status, detail) = check(ids);
        let cls = if status == "PASS" { "pass" } else { "fail" };
        format!("<tr><td>{req}</td><td>{rules}</td><td class=\"{cls}\">{status}</td><td>{detail}</td></tr>")
    }).collect::<Vec<_>>().join("\n");

    format!(
        r#"<table class="dengbao-table"><thead><tr><th>等保要求</th><th>规则</th><th>状态</th><th>详情</th></tr></thead><tbody>{rows_html}</tbody></table>"#
    )
}

fn build_top_findings(findings: &[Finding]) -> String {
    findings
        .iter()
        .take(10)
        .map(|f| {
            let sev = format!("{:?}", f.severity).to_lowercase();
            format!(
                "<tr><td>{sev}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                f.rule_id, f.title, f.recommendation
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{Finding, Severity};

    fn f(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity,
            category: "test".into(),
            title: "Test".into(),
            file: "test.json".into(),
            server_name: "test".into(),
            line: None,
            evidence: "ev".into(),
            recommendation: "fix".into(),
            auto_fixable: false,
            references: Vec::new(),
        }
    }

    #[test]
    fn test_build_html_audit_contains_doctype() {
        let findings = vec![f("no-tls", Severity::Medium)];
        let html = build_html_audit("test", &findings, 75, "B");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("75"));
        assert!(html.contains("B"));
        assert!(html.contains("no-tls"));
    }

    #[test]
    fn test_build_html_management_has_charts() {
        let findings = vec![
            f("no-tls", Severity::Medium),
            f("hardcoded-api-key", Severity::Critical),
        ];
        let html = build_html_management("test", &findings, 50, "D", 1, 100);
        assert!(html.contains("bar-track"));
        assert!(html.contains("Management Report"));
        assert!(html.contains("Dengbao"));
    }

    #[test]
    fn test_build_html_probe_contains_target() {
        let findings = vec![crate::probe::types::ProbeFinding {
            rule_id: "ssrf-probe".into(),
            severity: Severity::Critical,
            category: "network".into(),
            title: "SSRF".into(),
            target: "https://test.com".into(),
            evidence: "proof".into(),
            recommendation: "fix".into(),
        }];
        let html = build_html_probe("https://test.com", &findings);
        assert!(html.contains("https://test.com"));
        assert!(html.contains("ssrf-probe"));
    }

    #[test]
    fn test_build_dengbao_table_has_six_rows() {
        let html = build_dengbao_table(&[]);
        assert!(html.contains("访问控制"));
        assert!(html.contains("网络安全"));
        assert!(html.contains("PASS"));
    }

    #[test]
    fn test_critical_is_red() {
        let findings = vec![f("hardcoded-api-key", Severity::Critical)];
        let html = build_html_management("test", &findings, 0, "F", 1, 0);
        assert!(html.contains("#ff4444"));
    }
}
