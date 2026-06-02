use super::types::{AuditChain, AuditRecord};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub fn load_key(key_path: Option<&str>) -> Result<Vec<u8>, String> {
    if let Some(path) = key_path {
        let p = Path::new(path);
        if !p.exists() {
            return Err(format!("Audit key file not found: {path}"));
        }
        fs::read(p).map_err(|e| format!("Failed to read key file: {e}"))
    } else if let Ok(env_key) = std::env::var("HERMES_AUDIT_KEY") {
        let p = Path::new(&env_key);
        if p.exists() {
            fs::read(p).map_err(|e| format!("Failed to read key file from HERMES_AUDIT_KEY: {e}"))
        } else {
            Ok(env_key.into_bytes())
        }
    } else {
        Err("No audit key provided. Use --audit-key or set HERMES_AUDIT_KEY".into())
    }
}

pub fn secret_hash(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    format!("sha256:{:x}", hasher.finalize())
}

pub fn compute_hmac(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

pub fn hash_chain(prev_hmac: &[u8], record_data: &str) -> String {
    compute_hmac(prev_hmac, record_data.as_bytes())
}

pub fn build_chain(
    key: &[u8],
    command: &str,
    records: Vec<AuditRecord>,
) -> Result<AuditChain, String> {
    let hash = secret_hash(key);
    let mut chain = AuditChain::new(hash);
    let mut prev_hmac = key.to_vec();

    for mut record in records {
        let data = format!(
            "{}|{}|{}|{}|{}|{}",
            record.timestamp,
            record.rule_id,
            record.severity,
            record.target,
            record.finding,
            record.recommendation,
        );
        record.hmac = hash_chain(&prev_hmac, &data);
        prev_hmac =
            hex::decode(&record.hmac).map_err(|e| format!("Invalid HMAC hex in chain: {e}"))?;
        chain.records.push(record);
    }

    let _ = command;
    Ok(chain)
}

pub fn save_chain(chain: &AuditChain, command: &str) -> Result<String, String> {
    let dir = Path::new(".hermes");
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| format!("Cannot create .hermes: {e}"))?;
    }
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("chain-{command}-{ts}.json");
    let path = dir.join(&filename);
    let json = serde_json::to_string_pretty(chain)
        .map_err(|e| format!("Failed to serialize chain: {e}"))?;
    fs::write(&path, json).map_err(|e| format!("Failed to write chain file: {e}"))?;
    Ok(path.display().to_string())
}

pub fn verify_chain(chain: &AuditChain, key: &[u8]) -> Result<bool, String> {
    if chain.records.is_empty() {
        return Ok(true);
    }
    let expected_hash = secret_hash(key);
    if chain.secret_hash != expected_hash {
        return Ok(false);
    }
    let mut prev_hmac = key.to_vec();
    for record in &chain.records {
        let data = format!(
            "{}|{}|{}|{}|{}|{}",
            record.timestamp,
            record.rule_id,
            record.severity,
            record.target,
            record.finding,
            record.recommendation,
        );
        let expected = hash_chain(&prev_hmac, &data);
        if record.hmac != expected {
            return Ok(false);
        }
        prev_hmac =
            hex::decode(&record.hmac).map_err(|e| format!("Invalid HMAC hex in chain: {e}"))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(index: u64, rule: &str) -> AuditRecord {
        AuditRecord {
            index,
            timestamp: "2026-01-01T00:00:00Z".into(),
            rule_id: rule.into(),
            severity: "high".into(),
            target: "test.json".into(),
            finding: "Test finding".into(),
            recommendation: "Fix it".into(),
            hmac: String::new(),
        }
    }

    #[test]
    fn test_build_chain() {
        let key = b"test-key-16bytes!";
        let records = vec![
            make_record(1, "no-tls"),
            make_record(2, "hardcoded-api-key"),
        ];
        let chain = build_chain(key, "audit", records).unwrap();
        assert_eq!(chain.records.len(), 2);
        assert!(!chain.records[0].hmac.is_empty());
        assert!(!chain.records[1].hmac.is_empty());
        assert_ne!(chain.records[0].hmac, chain.records[1].hmac);
    }

    #[test]
    fn test_empty_chain() {
        let key = b"test-key-16bytes!";
        let chain = build_chain(key, "audit", vec![]).unwrap();
        assert!(chain.records.is_empty());
    }

    #[test]
    fn test_verify_valid_chain() {
        let key = b"test-key-16bytes!";
        let records = vec![make_record(1, "no-tls")];
        let chain = build_chain(key, "audit", records).unwrap();
        assert!(verify_chain(&chain, key).unwrap());
    }

    #[test]
    fn test_verify_tampered_chain() {
        let key = b"test-key-16bytes!";
        let records = vec![make_record(1, "no-tls")];
        let mut chain = build_chain(key, "audit", records).unwrap();
        chain.records[0].finding = "TAMPERED".into();
        assert!(!verify_chain(&chain, key).unwrap());
    }

    #[test]
    fn test_verify_wrong_key() {
        let key = b"test-key-16bytes!";
        let wrong_key = b"wrong-key-16bytes";
        let records = vec![make_record(1, "no-tls")];
        let chain = build_chain(key, "audit", records).unwrap();
        assert!(!verify_chain(&chain, wrong_key).unwrap());
    }

    #[test]
    fn test_secret_hash_deterministic() {
        let key = b"secret-16bytes!!!";
        let h1 = secret_hash(key);
        let h2 = secret_hash(key);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn test_secret_hash_different_keys() {
        let h1 = secret_hash(b"key1");
        let h2 = secret_hash(b"key2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_hmac_hex() {
        let key = b"test-key-16bytes!";
        let hmac = compute_hmac(key, b"hello world");
        assert_eq!(hmac.len(), 64);
        assert!(hmac.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_hmac_deterministic() {
        let key = b"test-key-16bytes!";
        let h1 = compute_hmac(key, b"data");
        let h2 = compute_hmac(key, b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_hmac_different_data() {
        let key = b"test-key-16bytes!";
        let h1 = compute_hmac(key, b"data1");
        let h2 = compute_hmac(key, b"data2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_load_key_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("hermes_test_key.bin");
        std::fs::write(&path, b"my-secret-key-123").unwrap();
        let key = load_key(Some(&path.to_string_lossy())).unwrap();
        assert_eq!(key, b"my-secret-key-123");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_key_file_not_found() {
        let result = load_key(Some("/nonexistent/key.bin"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_load_key_no_key_provided() {
        std::env::remove_var("HERMES_AUDIT_KEY");
        let result = load_key(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_chain() {
        let key = b"test-key-16bytes!";
        let records = vec![make_record(1, "no-tls")];
        let chain = build_chain(key, "audit-save-load", records).unwrap();
        let saved_path = save_chain(&chain, "audit-save-load").unwrap();
        assert!(std::path::Path::new(&saved_path).exists());
        assert!(saved_path.contains("chain-audit-save-load"));
        let _ = std::fs::remove_file(&saved_path);
    }
}
