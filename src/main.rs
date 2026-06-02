mod audit;
mod chain;
mod fuzz;
mod policy;
mod probe;
mod report;

use audit::types::{compute_score, Severity};
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::process;
use std::time::Instant;

const P0_RULES: &[&str] = &[
    "hardcoded-api-key",
    "hardcoded-password",
    "dangerous-command",
    "overly-permissive",
    "no-tls",
    "no-authentication",
    "bind-public-interface",
    "auto-approve",
    "env-secret-leak",
    "sensitive-file-args",
    "unsafe-filesystem",
    "unpinned-package",
    "supply-chain-risk",
    "no-timeout",
    "missing-description",
];

const P0_RULES_RICH: &[(&str, &str, &str)] = &[
    ("hardcoded-api-key", "Hardcoded API key detected", "Replace with ${ENV_VAR}"),
    ("hardcoded-password", "Hardcoded password detected", "Replace with ${ENV_VAR}"),
    ("dangerous-command", "Dangerous shell command", "Remove pipe-to-shell patterns"),
    ("overly-permissive", "Overly permissive tool access", "Explicitly list allowed tools"),
    ("no-tls", "No TLS encryption", "Use HTTPS URL"),
    ("no-authentication", "No authentication configured", "Add apiKey or Authorization header"),
    ("bind-public-interface", "Server bound to public interface", "Bind to 127.0.0.1"),
    ("auto-approve", "Auto-approval with wildcard", "Remove * from autoApprove"),
    ("env-secret-leak", "Environment variable leaks secret", "Use ${VAR} reference"),
    ("sensitive-file-args", "Sensitive file in startup args", "Use environment variables"),
    ("unsafe-filesystem", "Filesystem root directory access", "Restrict to specific directories"),
];

#[derive(ValueEnum, Clone, Debug)]
enum Format {
    Json,
    Html,
    HtmlManagement,
    Sarif,
}

#[derive(Parser)]
#[command(name = "hermes", version, about = "MCP Security Scanner & Compliance Auditor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, help = "Output format")]
    format: Option<Format>,

    #[arg(long, global = true, help = "Write output to file")]
    output: Option<String>,

    #[arg(long, global = true, help = "Verbose output to stderr")]
    verbose: bool,

    #[arg(long, global = true, help = "Disable colored output")]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Static security audit of MCP configuration files")]
    Audit {
        #[arg(help = "Path to MCP config file or directory", required_unless_present = "init_key")]
        path: Option<String>,

        #[arg(long, help = "Path to HMAC audit chain key file")]
        audit_key: Option<String>,

        #[arg(long, help = "Generate a new HMAC audit chain key file")]
        init_key: bool,

        #[arg(long = "policy", help = "Path to JSON policy file")]
        policy_file: Option<String>,

        #[arg(long = "preset", help = "Built-in policy preset")]
        preset: Option<String>,

        #[arg(long = "min-severity", help = "Minimum severity to show (info/low/medium/high/critical)")]
        min_severity: Option<String>,

        #[arg(long, help = "Auto-fix fixable findings in-place")]
        fix: bool,

        #[arg(long, requires = "fix", help = "Preview fixes without writing")]
        dry_run: bool,
    },

    #[command(about = "Runtime security probe of a running MCP Server")]
    Probe {
        #[arg(help = "URL of the MCP Server")]
        url: String,

        #[arg(long, default_value = "30", help = "Probe timeout in seconds")]
        timeout: u64,

        #[arg(long, help = "Path to HMAC audit chain key file")]
        audit_key: Option<String>,

        #[arg(long = "policy", help = "Path to JSON policy file")]
        policy_file: Option<String>,

        #[arg(long = "preset", help = "Built-in policy preset")]
        preset: Option<String>,

        #[arg(long = "min-severity", help = "Minimum severity to show (info/low/medium/high/critical)")]
        min_severity: Option<String>,
    },

    #[command(about = "Verify an HMAC audit chain file")]
    Verify {
        #[arg(help = "Path to audit chain JSON file")]
        audit_file: String,

        #[arg(long, help = "Path to HMAC audit chain key file")]
        audit_key: Option<String>,
    },

    #[command(about = "Fuzz-test a running MCP Server with malformed inputs")]
    Fuzz {
        #[arg(help = "URL of the MCP Server")]
        url: String,

        #[arg(long, default_value = "30", help = "Fuzz timeout in seconds")]
        timeout: u64,
    },

    #[command(about = "Render a JSON scan result file as formatted report")]
    Report {
        #[arg(help = "Path to JSON scan result file")]
        path: String,
    },

    #[command(about = "Generate a default .hermes-policy.json file")]
    Policy {
        #[arg(long, help = "Template preset (dengbao, basic, strict, enterprise)")]
        template: Option<String>,
    },
}

fn main() {
    color_eyre::install().ok();

    let cli = Cli::parse();

    if cli.no_color {
        console::set_colors_enabled(false);
    }

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("hermes=debug")
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    }

    let exit_code = match cli.command {
        Commands::Audit { path, audit_key, init_key, policy_file, preset, min_severity, fix, dry_run } => {
            if init_key {
                run_init_key(audit_key.as_deref())
            } else if let Some(p) = path {
                let policy = resolve_policy(policy_file.as_deref(), preset.as_deref(), min_severity.as_deref());
                let args = AuditArgs {
                    path: &p, format: cli.format, verbose: cli.verbose, output: cli.output.as_deref(),
                    audit_key: audit_key.as_deref(), policy: &policy, fix, dry_run,
                };
                run_audit(&args)
            } else {
                eprintln!("hermes: missing required argument <PATH>");
                1
            }
        }
        Commands::Probe { url, timeout, audit_key, policy_file, preset, min_severity } => {
            let policy = resolve_policy(policy_file.as_deref(), preset.as_deref(), min_severity.as_deref());
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_probe(&url, timeout, cli.format, cli.verbose, cli.output.as_deref(), audit_key.as_deref(), &policy))
        }
        Commands::Verify { audit_file, audit_key } => {
            run_verify(&audit_file, audit_key.as_deref(), cli.verbose)
        }
        Commands::Fuzz { url, timeout } => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_fuzz(&url, timeout, cli.format, cli.verbose, cli.output.as_deref()))
        }
        Commands::Report { path } => {
            run_report(&path, cli.format, cli.verbose, cli.output.as_deref())
        }
        Commands::Policy { template } => {
            run_policy_init(template.as_deref())
        }
    };

    process::exit(exit_code);
}

fn write_output(content: &str, output: Option<&str>) {
    if let Some(path) = output {
        if let Err(e) = fs::write(path, content) {
            eprintln!("hermes: failed to write output to {path}: {e}");
        }
    }
    println!("{content}");
}

struct AuditArgs<'a> {
    path: &'a str,
    format: Option<Format>,
    verbose: bool,
    output: Option<&'a str>,
    audit_key: Option<&'a str>,
    policy: &'a Option<policy::types::PolicyConfig>,
    fix: bool,
    dry_run: bool,
}

fn run_audit(args: &AuditArgs) -> i32 {
    let path = args.path;
    let format = args.format.as_ref();
    let verbose = args.verbose;
    let output = args.output;
    let audit_key = args.audit_key;
    let policy = args.policy;
    let fix = args.fix;
    let dry_run = args.dry_run;
    let start = Instant::now();
    let result = audit::scanner::scan_path(path);

    if verbose {
        tracing::debug!("scanned {} config files, {} skipped, {} errors",
            result.configs.len(), result.skipped.len(), result.errors.len());
    }

    if !result.errors.is_empty() {
        for e in &result.errors {
            eprintln!("hermes: {e}");
        }
        return 1;
    }

    for w in &result.warnings {
        eprintln!("hermes: {w}");
    }

    if !result.skipped.is_empty() {
        for s in &result.skipped {
            eprintln!("hermes: skipped: {s}");
        }
    }

    if result.configs.is_empty() {
        return 0;
    }

    let mut all_findings = Vec::new();

    for config in &result.configs {
        for (server_name, server) in &config.servers {
            for rule_id in P0_RULES {
                if let Some(finding) =
                    audit::rules::scan_server(rule_id, server_name, server, &config.file_path)
                {
                    all_findings.push(finding);
                }
            }
        }
    }

    if let Some(ref p) = policy {
        policy::engine::apply_policy(&mut all_findings, p);
    }

    let files_scanned = result.configs.len();
    let (score, grade) = compute_score(&all_findings);
    let duration_ms = start.elapsed().as_millis() as u64;
    let auto_fixable = all_findings.iter().filter(|f| f.auto_fixable).count();

    let critical = count_audit(&all_findings, &Severity::Critical);
    let high = count_audit(&all_findings, &Severity::High);
    let medium = count_audit(&all_findings, &Severity::Medium);
    let low = count_audit(&all_findings, &Severity::Low);
    let info = count_audit(&all_findings, &Severity::Info);

    if verbose {
        tracing::debug!("audit complete: {} findings, score={}, grade={}, {}ms",
            all_findings.len(), score, grade, duration_ms);
    }

    if matches!(format, Some(Format::Json)) {
        let report = report::json::build_audit_json(
            path, &all_findings, files_scanned, duration_ms, auto_fixable,
        );
        write_output(&report::json::to_json(&report), output);
    } else if matches!(format, Some(Format::Html)) {
        let html = report::html::build_html_audit(path, &all_findings, score, &grade);
        write_output(&html, output);
    } else if matches!(format, Some(Format::Sarif)) {
        let sarif = report::sarif::build_sarif(path, &all_findings, P0_RULES_RICH);
        write_output(&sarif, output);
    } else if matches!(format, Some(Format::HtmlManagement)) {
        let html = report::html::build_html_management(path, &all_findings, score, &grade, files_scanned, duration_ms);
        write_output(&html, output);
    } else {
        report::terminal::print_header(path, "Audit");
        report::terminal::print_score(score, &grade);
        let stats = report::terminal::ScanStats {
            total: all_findings.len(), critical, high, medium, low, info,
            duration_ms, items_scanned: String::new(), files_scanned,
        };
        report::terminal::print_audit_summary(&stats);
        report::terminal::print_audit_findings(&all_findings);
        if let Some(out_path) = output {
            let plain = report::terminal::build_audit_report(
                path, score, &grade, &stats, &all_findings,
            );
            if let Err(e) = fs::write(out_path, &plain) {
                eprintln!("hermes: failed to write output to {out_path}: {e}");
            }
        }
    }

    if fix || dry_run {
        audit::fixer::apply_fixes_from_findings(&all_findings, dry_run);
    }

    if let Some(key_path) = audit_key {
        save_audit_chain(key_path, "audit", &all_findings);
    }

    if all_findings.is_empty() { 0 } else { 2 }
}

async fn run_probe(url: &str, timeout: u64, format: Option<Format>, verbose: bool, output: Option<&str>, audit_key: Option<&str>, _policy: &Option<policy::types::PolicyConfig>) -> i32 {
    let start = Instant::now();
    let ctx = probe::types::ProbeContext::new(url, timeout);

    eprintln!("Probing {} ...", ctx.target_url);

    if verbose {
        tracing::debug!("starting probe of {} with {}s timeout", ctx.target_url, ctx.timeout_secs);
    }

    let mut all_findings: Vec<probe::types::ProbeFinding> = Vec::new();

    let tls_fut = probe::tls::probe_tls(&ctx);
    let auth_fut = probe::auth::probe_auth(&ctx);
    let tools_fut = probe::tools::probe_tools(&ctx);
    let ssrf_fut = probe::ssrf::probe_ssrf(&ctx);
    let traversal_fut = probe::traversal::probe_path_traversal(&ctx);
    let session_fut = probe::session::probe_session(&ctx);
    let redirect_fut = probe::redirect::probe_ssrf_redirect(&ctx);
    let replay_fut = probe::replay::probe_session_replay(&ctx);
    let fixation_fut = probe::fixation::probe_session_fixation(&ctx);
    let deputy_fut = probe::deputy::probe_confused_deputy(&ctx);
    let passthrough_fut = probe::passthrough::probe_token_passthrough(&ctx);
    let scope_fut = probe::passthrough::probe_scope_minimization(&ctx);

    let (tls_result, auth_result, tools_result, ssrf_result, traversal_result, session_result,
         redirect_result, replay_result, fixation_result, deputy_result, passthrough_result, scope_result) =
        tokio::join!(tls_fut, auth_fut, tools_fut, ssrf_fut, traversal_fut, session_fut,
                     redirect_fut, replay_fut, fixation_fut, deputy_fut, passthrough_fut, scope_fut);

    all_findings.extend(tls_result);
    all_findings.extend(auth_result);
    all_findings.extend(tools_result.findings);
    all_findings.extend(ssrf_result);
    all_findings.extend(traversal_result);
    all_findings.extend(session_result);
    all_findings.extend(redirect_result);
    all_findings.extend(replay_result);
    all_findings.extend(fixation_result);
    all_findings.extend(deputy_result);
    all_findings.extend(passthrough_result);
    all_findings.extend(scope_result);
    let tools = tools_result.tools;

    let duration_ms = start.elapsed().as_millis() as u64;

    let total = all_findings.len();
    let critical = count_probe(&all_findings, &Severity::Critical);
    let high = count_probe(&all_findings, &Severity::High);
    let medium = count_probe(&all_findings, &Severity::Medium);
    let low = count_probe(&all_findings, &Severity::Low);
    let info = count_probe(&all_findings, &Severity::Info);

    let (score, grade) = compute_probe_score(&all_findings);

    if verbose {
        tracing::debug!("probe complete: {} findings, score={}, grade={}, {}ms",
            total, score, grade, duration_ms);
    }

    if matches!(format, Some(Format::Json)) {
        let json_report = serde_json::json!({
            "tool": "hermes",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "probe",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "target": ctx.target_url,
            "score": {
                "grade": grade,
                "numeric": score,
            },
            "summary": {
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "duration_ms": duration_ms,
            },
            "tools_discovered": tools,
            "findings": all_findings,
        });
        write_output(&serde_json::to_string_pretty(&json_report).unwrap(), output);
    } else if matches!(format, Some(Format::Html)) {
        let html = report::html::build_html_probe(&ctx.target_url, &all_findings);
        write_output(&html, output);
    } else {
        report::terminal::print_header(&ctx.target_url, "Probe");
        report::terminal::print_score(score, &grade);
        let probe_stats = report::terminal::ScanStats {
            total, critical, high, medium, low, info, duration_ms,
            items_scanned: String::new(), files_scanned: 0,
        };
        report::terminal::print_probe_summary(&probe_stats);
        report::terminal::print_probe_findings(&all_findings, &tools);
        if let Some(out_path) = output {
            let plain = report::terminal::build_probe_report(
                &ctx.target_url, &probe_stats, &all_findings, &tools,
            );
            if let Err(e) = fs::write(out_path, &plain) {
                eprintln!("hermes: failed to write output to {out_path}: {e}");
            }
        }
    }

    if let Some(key_path) = audit_key {
        let records: Vec<chain::types::AuditRecord> = all_findings.iter().enumerate().map(|(i, f)| {
            chain::types::AuditRecord {
                index: i as u64 + 1,
                timestamp: chrono::Utc::now().to_rfc3339(),
                rule_id: f.rule_id.clone(),
                severity: format!("{:?}", f.severity).to_lowercase(),
                target: url.to_string(),
                finding: f.evidence.clone(),
                recommendation: f.recommendation.clone(),
                hmac: String::new(),
            }
        }).collect();
        save_audit_chain_direct(key_path, "probe", records);
    }

    if all_findings.iter().any(|f| f.severity >= Severity::High) { 2 } else { 0 }
}

fn compute_probe_score(findings: &[probe::types::ProbeFinding]) -> (u32, String) {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count() as u32;
    let high = findings.iter().filter(|f| f.severity == Severity::High).count() as u32;
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count() as u32;

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

fn count_audit(findings: &[audit::types::Finding], severity: &Severity) -> usize {
    findings.iter().filter(|f| &f.severity == severity).count()
}

fn count_probe(findings: &[probe::types::ProbeFinding], severity: &Severity) -> usize {
    findings.iter().filter(|f| &f.severity == severity).count()
}

fn save_audit_chain(key_path: &str, command: &str, findings: &[audit::types::Finding]) {
    let records: Vec<chain::types::AuditRecord> = findings.iter().enumerate().map(|(i, f)| {
        chain::types::AuditRecord {
            index: i as u64 + 1,
            timestamp: chrono::Utc::now().to_rfc3339(),
            rule_id: f.rule_id.clone(),
            severity: format!("{:?}", f.severity).to_lowercase(),
            target: f.file.clone(),
            finding: f.evidence.clone(),
            recommendation: f.recommendation.clone(),
            hmac: String::new(),
        }
    }).collect();
    save_audit_chain_direct(key_path, command, records);
}

fn save_audit_chain_direct(key_path: &str, command: &str, records: Vec<chain::types::AuditRecord>) {
    match chain::hmac::load_key(Some(key_path)) {
        Ok(key) => {
            match chain::hmac::build_chain(&key, command, records) {
                Ok(chain) => match chain::hmac::save_chain(&chain, command) {
                    Ok(path) => eprintln!("Audit chain saved: {path}"),
                    Err(e) => eprintln!("hermes: failed to save audit chain: {e}"),
                },
                Err(e) => eprintln!("hermes: failed to build audit chain: {e}"),
            }
        }
        Err(e) => eprintln!("hermes: {e}"),
    }
}

fn run_init_key(path: Option<&str>) -> i32 {
    use ring::rand::{SecureRandom, SystemRandom};
    let default_path = ".hermes/audit.key";
    let target = path.unwrap_or(default_path);

    if let Some(parent) = std::path::Path::new(target).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("hermes: cannot create directory: {e}");
                return 1;
            }
        }
    }

    let mut key = vec![0u8; 32];
    let rng = SystemRandom::new();
    rng.fill(&mut key).unwrap();

    if let Err(e) = fs::write(target, &key) {
        eprintln!("hermes: failed to write key file {target}: {e}");
        return 1;
    }

    println!("Audit key created: {target} (32 bytes)");
    println!("Keep this file secure. Use it with --audit-key for auditable scans.");
    0
}

fn run_verify(path: &str, audit_key: Option<&str>, verbose: bool) -> i32 {
    match chain::verify::verify_chain_file(path, audit_key) {
        Ok((chain, true)) => {
            if verbose {
                eprintln!(
                    "Chain is valid — {} records, algorithm: {}",
                    chain.records.len(),
                    chain.algorithm
                );
            }
            println!(
                "Chain verified: {} records — VALID",
                chain.records.len()
            );
            0
}
        Ok((chain, false)) => {
            if verbose {
                eprintln!(
                    "Chain verification FAILED — {} records, algorithm: {}",
                    chain.records.len(),
                    chain.algorithm
                );
            }
            eprintln!("Chain is INVALID — records may have been tampered with");
            2
        }
        Err(e) => {
            eprintln!("hermes: {e}");
            1
        }
    }
}

fn resolve_policy(
    policy_file: Option<&str>,
    preset: Option<&str>,
    min_severity: Option<&str>,
) -> Option<policy::types::PolicyConfig> {
    let sev = min_severity.map(|s| s.to_string());
    match (policy_file, preset) {
        (Some(_), Some(_)) => {
            eprintln!("hermes: --policy and --preset are mutually exclusive");
            None
        }
        (Some(path), None) => match policy::parser::load_policy(path) {
            Ok(mut p) => {
                if sev.is_some() && p.min_severity.is_none() {
                    p.min_severity = sev;
                }
                Some(p)
            }
            Err(e) => { eprintln!("hermes: {e}"); None }
        },
        (None, Some("dengbao")) => {
            let preset = policy::presets::dengbao_preset();
            let mut rules = std::collections::HashMap::new();
            for (rule_id, enabled) in &preset.rule_state {
                rules.insert(rule_id.clone(), policy::types::RuleEntry { enabled: *enabled, severity: None });
            }
            Some(policy::types::PolicyConfig { version: 1, name: "dengbao".into(),
                min_severity: sev.or_else(|| preset.min_severity.map(|s| policy::types::severity_to_str(&s).to_string())),
                rules, exceptions: vec![], preset_mode: true })
        }
        (None, Some("basic")) => presets_helper(&policy::presets::basic_preset(), sev),
        (None, Some("strict")) => presets_helper(&policy::presets::strict_preset(), sev),
        (None, Some("enterprise")) => presets_helper(&policy::presets::enterprise_preset(), sev),
        (None, Some(other)) => {
            eprintln!("hermes: unknown preset '{other}'. Available: dengbao, basic, strict, enterprise");
            None
        }
        (None, None) => {
            sev.map(|s| policy::types::PolicyConfig {
                version: 1,
                name: String::new(),
                min_severity: Some(s),
                rules: std::collections::HashMap::new(),
                exceptions: vec![],
                preset_mode: false,
            })
        }
    }
}

fn presets_helper(preset: &policy::types::BuiltinPreset, sev: Option<String>) -> Option<policy::types::PolicyConfig> {
    let mut rules = std::collections::HashMap::new();
    for (rule_id, enabled) in &preset.rule_state {
        rules.insert(rule_id.clone(), policy::types::RuleEntry { enabled: *enabled, severity: None });
    }
    Some(policy::types::PolicyConfig {
        version: 1,
        name: preset.name.clone(),
        min_severity: sev.or_else(|| preset.min_severity.map(|s| policy::types::severity_to_str(&s).to_string())),
        rules,
        exceptions: vec![],
        preset_mode: true,
    })
}

async fn run_fuzz(url: &str, timeout: u64, format: Option<Format>, verbose: bool, output: Option<&str>) -> i32 {
    eprintln!("Fuzzing {url} ...");

    if verbose {
        tracing::debug!("starting fuzz of {} with {}s timeout", url, timeout);
    }

    let ctx = fuzz::types::FuzzContext::new(url, timeout);
    let test_ids: &[&str] = &["FZ-01", "FZ-02", "FZ-03", "FZ-04"];
    let results = fuzz::engine::run_fuzz(&ctx, test_ids).await;

    let crashed = results.iter().filter(|r| r.severity >= crate::audit::types::Severity::High).count();

    if matches!(format, Some(Format::Json)) {
        let json = serde_json::json!({
            "tool": "hermes",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "fuzz",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "target": ctx.target_url,
            "summary": {
                "total_tests": results.len(),
                "crashed": crashed,
            },
            "results": results,
        });
        write_output(&serde_json::to_string_pretty(&json).unwrap(), output);
    } else {
        report::terminal::print_header(&ctx.target_url, "Fuzz");
        println!("  Tests executed: {}", results.len());
        println!("  High/Critical issues: {crashed}\n");
        for r in &results {
            if r.severity >= crate::audit::types::Severity::High {
                let sev = format!("{:?}", r.severity).to_uppercase();
                println!("  [{sev}] {test} on {tool}", sev = sev, test = r.test_id, tool = r.tool_name);
                println!("        {}\n", r.evidence);
            }
        }
    }

    if crashed > 0 { 2 } else { 0 }
}

fn run_report(path: &str, format: Option<Format>, verbose: bool, output: Option<&str>) -> i32 {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hermes: cannot read {path}: {e}");
            return 1;
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hermes: invalid JSON in {path}: {e}");
            return 1;
        }
    };

    if verbose {
        tracing::debug!("rendering report from {path}");
    }

    if matches!(format, Some(Format::Html)) {
        let target = json.get("target").and_then(|v| v.as_str()).unwrap_or("unknown");
        let findings: Vec<crate::probe::types::ProbeFinding> =
            serde_json::from_value(json.get("findings").cloned().unwrap_or_default())
                .unwrap_or_default();
        let html = report::html::build_html_probe(target, &findings);
        write_output(&html, output);
    } else {
        let pretty = serde_json::to_string_pretty(&json).unwrap_or_default();
        write_output(&pretty, output);
    }

    0
}

fn run_policy_init(template: Option<&str>) -> i32 {
    let target = ".hermes-policy.json";
    if std::path::Path::new(target).exists() {
        eprintln!("hermes: {target} already exists");
        return 1;
    }
    let config = match template {
        Some("dengbao") => presets_helper(&policy::presets::dengbao_preset(), None),
        Some("basic") => presets_helper(&policy::presets::basic_preset(), None),
        Some("strict") => presets_helper(&policy::presets::strict_preset(), None),
        Some("enterprise") => presets_helper(&policy::presets::enterprise_preset(), None),
        Some(other) => {
            eprintln!("hermes: unknown template '{other}'. Available: dengbao, basic, strict, enterprise");
            return 1;
        }
        None => Some(policy::types::PolicyConfig {
            version: 1,
            name: "Default MCP Security Policy".into(),
            min_severity: Some("medium".into()),
            rules: std::collections::HashMap::new(),
            exceptions: vec![],
            preset_mode: false,
        }),
    };
    if let Some(config) = config {
        let json = serde_json::to_string_pretty(&config).unwrap_or_default();
        if let Err(e) = fs::write(target, json) {
            eprintln!("hermes: cannot write {target}: {e}");
            return 1;
        }
        println!("Policy file created: {target}");
    }
    0
}
