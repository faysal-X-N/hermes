use crate::audit::parser::ServerConfig;
use crate::audit::types::Finding;
use std::collections::HashSet;
use std::fs;

pub fn apply_fixes_from_findings(findings: &[Finding], dry_run: bool) {
    let auto_fixable: Vec<&Finding> = findings.iter().filter(|f| f.auto_fixable).collect();

    if auto_fixable.is_empty() {
        return;
    }

    let mut written = HashSet::new();

    for f in &auto_fixable {
        let json_str = match fs::read_to_string(&f.file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hermes: cannot read {}: {e}", f.file);
                continue;
            }
        };

        let mut root: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("hermes: invalid JSON in {}: {e}", f.file);
                continue;
            }
        };

        let servers = match root.get_mut("mcpServers") {
            Some(v) => v,
            None => continue,
        };

        let sv = match servers.get_mut(&f.server_name) {
            Some(v) => v,
            None => continue,
        };

        let obj = match sv.as_object_mut() {
            Some(o) => o,
            None => continue,
        };

        match f.rule_id.as_str() {
            "hardcoded-api-key" | "hardcoded-password" => {
                for key in &[
                    "apiKey",
                    "api_key",
                    "token",
                    "accessToken",
                    "secret",
                    "password",
                    "passwd",
                    "pwd",
                ] {
                    if let Some(val) = obj.get(*key) {
                        if val.is_string()
                            && !ServerConfig::is_env_var_ref(val.as_str().unwrap_or(""))
                        {
                            let env_name = f.server_name.to_uppercase().replace('-', "_");
                            let env_key = key
                                .to_uppercase()
                                .replace("APIKEY", "API_KEY")
                                .replace("ACCESSTOKEN", "TOKEN");
                            let new_val = format!("${{{env_name}_{env_key}}}");
                            if dry_run {
                                eprintln!(
                                    "  [DRY-RUN] {}: {}.{} → {new_val}",
                                    f.file, f.server_name, key
                                );
                            } else {
                                obj.insert(key.to_string(), serde_json::Value::String(new_val));
                            }
                        }
                    }
                }
            }
            "env-secret-leak" => {
                if let Some(env_obj) = obj.get_mut("env").and_then(|e| e.as_object_mut()) {
                    for (var, val) in env_obj.iter_mut() {
                        if val.is_string()
                            && !ServerConfig::is_env_var_ref(val.as_str().unwrap_or(""))
                            && val.as_str().unwrap_or("").len() > 4
                        {
                            let new_key = var.to_uppercase().replace('-', "_");
                            if dry_run {
                                eprintln!("  [DRY-RUN] {}: env.{var} → ${{{new_key}}}", f.file);
                            } else {
                                *val = serde_json::Value::String(format!("${{{new_key}}}"));
                            }
                        }
                    }
                }
            }
            "no-tls" => {
                if let Some(url) = obj.get("url") {
                    let url_str = url.as_str().unwrap_or("");
                    if url_str.starts_with("http://") {
                        let new_url = url_str.replacen("http://", "https://", 1);
                        if dry_run {
                            eprintln!("  [DRY-RUN] {}: {}.url → {new_url}", f.file, f.server_name);
                        } else {
                            obj.insert("url".into(), serde_json::Value::String(new_url));
                        }
                    }
                }
            }
            _ => {}
        }

        if !dry_run {
            let pretty = serde_json::to_string_pretty(&root).unwrap_or_default();
            if let Err(e) = fs::write(&f.file, pretty) {
                eprintln!("hermes: cannot write {}: {e}", f.file);
            } else {
                written.insert(&f.file);
            }
        }
    }

    for file in &written {
        eprintln!("Fixed: {file}");
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{Finding, Severity};
    use super::*;

    fn f(rule_id: &str, auto_fixable: bool) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: Severity::High,
            category: "test".into(),
            title: "Test".into(),
            file: "nonexistent.json".into(),
            server_name: "test".into(),
            line: None,
            evidence: "ev".into(),
            recommendation: "fix".into(),
            auto_fixable,
            references: Vec::new(),
        }
    }

    #[test]
    fn test_apply_fixes_empty_findings() {
        apply_fixes_from_findings(&[], true);
    }

    #[test]
    fn test_apply_fixes_non_fixable() {
        apply_fixes_from_findings(&[f("no-tls", false)], true);
    }

    #[test]
    fn test_apply_fixes_nonexistent_file_handles_gracefully() {
        apply_fixes_from_findings(&[f("hardcoded-api-key", true)], true);
    }
}
