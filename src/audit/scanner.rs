use crate::audit::parser::{McpConfig, ParsedConfig};
use std::fs;
use std::io::Read;
use std::path::Path;

const MAX_SCAN_DEPTH: usize = 3;

const CONFIG_NAMES: &[&str] = &["mcp.json", ".mcp.json", ".claude-mcp.json"];

struct ScanState {
    results: Vec<ParsedConfig>,
    skipped: Vec<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

pub fn scan_path(path: &str) -> ScanResult {
    if path == "-" {
        return scan_stdin();
    }

    if has_glob(path) {
        return scan_glob(path);
    }

    let p = Path::new(path);
    let mut state = ScanState {
        results: Vec::new(),
        skipped: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    if p.is_dir() {
        scan_directory(p, 0, &mut state);
    } else if p.is_file() {
        process_file(p, &mut state);
    } else {
        state.errors.push(format!("Path not found: {path}"));
    }

    if state.results.is_empty() && state.errors.is_empty() {
        state
            .warnings
            .push(format!("no MCP config files found in {path}"));
    }

    ScanResult {
        configs: state.results,
        skipped: state.skipped,
        errors: state.errors,
        warnings: state.warnings,
    }
}

fn has_glob(path: &str) -> bool {
    path.contains('*') || path.contains('?')
}

fn scan_glob(pattern: &str) -> ScanResult {
    let mut state = ScanState {
        results: Vec::new(),
        skipped: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    let is_recursive = pattern.contains("**");

    let base = if let Some(pos) = pattern.find('*') {
        let base_end = pattern[..pos].rfind(['/', '\\']).unwrap_or(0);
        let base_path = &pattern[..base_end];
        if base_path.is_empty() {
            "."
        } else {
            base_path
        }
    } else {
        pattern
    };

    let base_path = Path::new(base);
    if !base_path.exists() {
        state
            .errors
            .push(format!("Glob base path not found: {base}"));
        return ScanResult {
            configs: state.results,
            skipped: state.skipped,
            errors: state.errors,
            warnings: state.warnings,
        };
    }

    if is_recursive {
        scan_directory_recursive(base_path, 0, usize::MAX, &mut state, pattern);
    } else {
        scan_directory_recursive(base_path, 0, 1, &mut state, pattern);
    }

    if state.results.is_empty() && state.errors.is_empty() {
        state
            .warnings
            .push(format!("no MCP config files matching '{pattern}'"));
    }

    ScanResult {
        configs: state.results,
        skipped: state.skipped,
        errors: state.errors,
        warnings: state.warnings,
    }
}

fn scan_directory_recursive(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    state: &mut ScanState,
    pattern: &str,
) {
    if depth > max_depth {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let path_str = path.display().to_string();

        if path.is_dir() {
            scan_directory_recursive(&path, depth + 1, max_depth, state, pattern);
        } else if path.is_file() && matches_glob(&path_str, pattern) {
            process_file(&path, state);
        }
    }
}

fn matches_glob(path: &str, pattern: &str) -> bool {
    let path_normalized = path.replace('\\', "/");
    let pattern_normalized = pattern.replace('\\', "/");

    if pattern_normalized.contains("**") {
        match_globstar(&path_normalized, &pattern_normalized)
    } else {
        match_simple_glob(&path_normalized, &pattern_normalized)
    }
}

fn match_simple_glob(path: &str, pattern: &str) -> bool {
    let pb: Vec<char> = pattern.chars().collect();
    let sb: Vec<char> = path.chars().collect();

    let mut pi = 0;
    let mut si = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while si < sb.len() {
        if pi < pb.len() && (pb[pi] == sb[si] || pb[pi] == '?') {
            pi += 1;
            si += 1;
        } else if pi < pb.len() && pb[pi] == '*' {
            star_idx = Some(pi);
            match_idx = si;
            pi += 1;
        } else if let Some(si_idx) = star_idx {
            pi = si_idx + 1;
            match_idx += 1;
            si = match_idx;
        } else {
            return false;
        }
    }

    while pi < pb.len() && pb[pi] == '*' {
        pi += 1;
    }

    pi == pb.len()
}

fn match_globstar(path: &str, pattern: &str) -> bool {
    let pparts: Vec<&str> = pattern.split("**").collect();

    if pparts.is_empty() {
        return true;
    }

    let first = pparts[0];
    if !path.starts_with(first) {
        return false;
    }

    let mut remaining = &path[first.len()..];

    for i in 1..pparts.len() {
        let part = pparts[i];
        if part.is_empty() {
            continue;
        }

        if i == pparts.len() - 1 {
            // Last part must match the remaining suffix, using simple glob
            if let Some(part) = part.strip_prefix('/') {
                remaining = remaining.trim_start_matches('/');
                return match_glob_suffix(remaining, part);
            } else {
                return match_glob_suffix(remaining, part);
            }
        } else {
            // Find this part somewhere in the remaining string
            if let Some(pos) = remaining.find(part) {
                remaining = &remaining[pos + part.len()..];
            } else {
                return false;
            }
        }
    }

    true
}

fn match_glob_suffix(path: &str, pattern: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    let psegments: Vec<&str> = pattern.split('/').collect();

    if psegments.len() > segments.len() {
        return false;
    }

    let start = segments.len() - psegments.len();
    for (i, pseg) in psegments.iter().enumerate() {
        if !match_simple_glob(segments[start + i], pseg) {
            return false;
        }
    }
    true
}

fn scan_stdin() -> ScanResult {
    let mut state = ScanState {
        results: Vec::new(),
        skipped: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    let mut content = String::new();
    match std::io::stdin().read_to_string(&mut content) {
        Ok(_) => match parse_config_from_bytes(&content, "<stdin>") {
            Ok(config) => state.results.push(config),
            Err(err) => state.errors.push(err),
        },
        Err(err) => {
            state.errors.push(format!("Failed to read stdin: {err}"));
        }
    }

    ScanResult {
        configs: state.results,
        skipped: state.skipped,
        errors: state.errors,
        warnings: state.warnings,
    }
}

fn scan_directory(dir: &Path, depth: usize, state: &mut ScanState) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => {
            state
                .errors
                .push(format!("Cannot read directory {}: {}", dir.display(), err));
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_directory(&path, depth + 1, state);
        } else if path.is_file() {
            process_file(&path, state);
        }
    }
}

fn process_file(file: &Path, state: &mut ScanState) {
    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext != "json" && ext != "yaml" && ext != "yml" {
        return;
    }

    let content = match fs::read_to_string(file) {
        Ok(c) => c,
        Err(err) => {
            state
                .errors
                .push(format!("Cannot read {}: {}", file.display(), err));
            return;
        }
    };

    match parse_config_from_bytes(&content, &file.display().to_string()) {
        Ok(config) => state.results.push(config),
        Err(err) => {
            if CONFIG_NAMES.contains(&file_name) {
                state
                    .errors
                    .push(format!("Failed to parse {}: {}", file.display(), err));
            } else {
                state
                    .skipped
                    .push(format!("{} (unrecognized format)", file.display()));
            }
        }
    }
}

fn parse_config_from_bytes(content: &str, source: &str) -> Result<ParsedConfig, String> {
    let config = serde_json::from_str::<McpConfig>(content).or_else(|json_err| {
        serde_yaml_ng::from_str::<McpConfig>(content).map_err(|yaml_err| {
            format!("JSON parse error in {source}: {json_err}. YAML parse also failed: {yaml_err}")
        })
    })?;

    if config.mcp_servers.is_empty() {
        return Err("no mcpServers found".to_string());
    }

    Ok(ParsedConfig {
        file_path: source.to_string(),
        servers: config.mcp_servers,
        parse_errors: Vec::new(),
    })
}

pub struct ScanResult {
    pub configs: Vec<ParsedConfig>,
    pub skipped: Vec<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_glob_simple() {
        assert!(matches_glob("mcp.json", "*.json"));
        assert!(matches_glob("test.json", "*.json"));
        assert!(!matches_glob("test.yaml", "*.json"));
    }

    #[test]
    fn test_matches_glob_path() {
        assert!(matches_glob("configs/mcp.json", "configs/*.json"));
        assert!(matches_glob("a/b/c.json", "a/**/*.json"));
        assert!(matches_glob("a/c.json", "a/**/*.json"));
        assert!(!matches_glob("b/c.json", "a/**/*.json"));
    }

    #[test]
    fn test_scan_test_fixtures() {
        let result = scan_path("tests/fixtures/configs");
        assert_eq!(result.configs.len(), 2);
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn test_scan_glob_pattern() {
        let result = scan_path("tests/fixtures/configs/*.json");
        assert_eq!(result.configs.len(), 2);
    }

    #[test]
    fn test_has_glob() {
        assert!(has_glob("*.json"));
        assert!(has_glob("a/**/*.json"));
        assert!(has_glob("a/b?.json"));
        assert!(!has_glob("mcp.json"));
    }
}
