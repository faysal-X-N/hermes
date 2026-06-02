#![allow(clippy::uninlined_format_args)]

mod audit;
mod probe;
mod report;

use audit::types::{compute_score, Severity};
use clap::{Parser, Subcommand};
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
];

#[derive(Parser)]
#[command(name = "hermes", version, about = "MCP Security Scanner & Compliance Auditor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, help = "Output format (json)")]
    format: Option<String>,

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
        #[arg(help = "Path to MCP config file or directory")]
        path: String,
    },

    #[command(about = "Runtime security probe of a running MCP Server")]
    Probe {
        #[arg(help = "URL of the MCP Server")]
        url: String,

        #[arg(long, default_value = "30", help = "Probe timeout in seconds")]
        timeout: u64,
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
        Commands::Audit { path } => run_audit(&path, cli.format.as_deref(), cli.output.as_deref()),
        Commands::Probe { url, timeout } => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_probe(&url, timeout, cli.format.as_deref(), cli.output.as_deref()))
        }
    };

    process::exit(exit_code);
}

fn write_output(content: &str, output: Option<&str>) {
    if let Some(path) = output {
        let _ = fs::write(path, content);
        println!("{}", content);
    } else {
        println!("{}", content);
    }
}

fn run_audit(path: &str, format: Option<&str>, output: Option<&str>) -> i32 {
    let start = Instant::now();
    let result = audit::scanner::scan_path(path);

    if !result.errors.is_empty() {
        for e in &result.errors {
            eprintln!("hermes: {}", e);
        }
        return 1;
    }

    if !result.skipped.is_empty() {
        for s in &result.skipped {
            eprintln!("hermes: skipped: {}", s);
        }
    }

    if result.configs.is_empty() {
        eprintln!("hermes: no MCP config files found in {}", path);
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

    let files_scanned = result.configs.len();
    let (score, grade) = compute_score(&all_findings);
    let duration_ms = start.elapsed().as_millis() as u64;
    let auto_fixable = all_findings.iter().filter(|f| f.auto_fixable).count();

    let critical = count_audit(&all_findings, &Severity::Critical);
    let high = count_audit(&all_findings, &Severity::High);
    let medium = count_audit(&all_findings, &Severity::Medium);
    let low = count_audit(&all_findings, &Severity::Low);
    let info = count_audit(&all_findings, &Severity::Info);

    if format == Some("json") {
        let report = report::json::build_audit_json(
            path, &all_findings, files_scanned, duration_ms, auto_fixable,
        );
        write_output(&report::json::to_json(&report), output);
    } else {
        report::terminal::print_header(path, "Audit");
        report::terminal::print_score(score, &grade);
        report::terminal::print_audit_summary(
            all_findings.len(), critical, high, medium, low, info, files_scanned, duration_ms,
        );
        report::terminal::print_audit_findings(&all_findings);
        if let Some(out_path) = output {
            let plain = report::terminal::build_audit_report(
                path, score, &grade,
                all_findings.len(), critical, high, medium, low, info,
                files_scanned, duration_ms, &all_findings,
            );
            let _ = fs::write(out_path, plain);
        }
    }

    if all_findings.is_empty() { 0 } else { 2 }
}

async fn run_probe(url: &str, timeout: u64, format: Option<&str>, output: Option<&str>) -> i32 {
    let start = Instant::now();
    let ctx = probe::types::ProbeContext::new(url, timeout);

    eprintln!("Probing {} ...", ctx.target_url);

    let mut all_findings: Vec<probe::types::ProbeFinding> = Vec::new();

    let tls_fut = probe::tls::probe_tls(&ctx);
    let auth_fut = probe::auth::probe_auth(&ctx);
    let tools_fut = probe::tools::probe_tools(&ctx);

    let (tls_result, auth_result, tools_result) = tokio::join!(tls_fut, auth_fut, tools_fut);

    all_findings.extend(tls_result);
    all_findings.extend(auth_result);
    all_findings.extend(tools_result.findings);
    let tools = tools_result.tools;

    let duration_ms = start.elapsed().as_millis() as u64;

    let total = all_findings.len();
    let critical = count_probe(&all_findings, &Severity::Critical);
    let high = count_probe(&all_findings, &Severity::High);
    let medium = count_probe(&all_findings, &Severity::Medium);
    let low = count_probe(&all_findings, &Severity::Low);
    let info = count_probe(&all_findings, &Severity::Info);

    if format == Some("json") {
        let json_report = serde_json::json!({
            "tool": "hermes",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "probe",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "target": ctx.target_url,
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
    } else {
        report::terminal::print_header(&ctx.target_url, "Probe");
        report::terminal::print_probe_summary(
            total, critical, high, medium, low, info, duration_ms,
        );
        report::terminal::print_probe_findings(&all_findings, &tools);
        if let Some(out_path) = output {
            let plain = report::terminal::build_probe_report(
                &ctx.target_url, total, critical, high, medium, low, info,
                duration_ms, &all_findings, &tools,
            );
            let _ = fs::write(out_path, plain);
        }
    }

    if all_findings.iter().any(|f| f.severity >= Severity::High) { 2 } else { 0 }
}

fn count_audit(findings: &[audit::types::Finding], severity: &Severity) -> usize {
    findings.iter().filter(|f| &f.severity == severity).count()
}

fn count_probe(findings: &[probe::types::ProbeFinding], severity: &Severity) -> usize {
    findings.iter().filter(|f| &f.severity == severity).count()
}
