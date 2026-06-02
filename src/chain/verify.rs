use super::hmac;
use super::types::AuditChain;
use std::fs;

pub fn verify_chain_file(path: &str, key: Option<&str>) -> Result<(AuditChain, bool), String> {
    let content = fs::read_to_string(path).map_err(|e| format!("Cannot read file: {e}"))?;
    let chain: AuditChain =
        serde_json::from_str(&content).map_err(|e| format!("Invalid chain JSON: {e}"))?;
    let key_bytes = hmac::load_key(key)?;
    let valid = hmac::verify_chain(&chain, &key_bytes)?;
    Ok((chain, valid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::hmac;

    #[test]
    fn test_verify_chain_file_valid() {
        let key = b"test-key-16bytes!";
        let records = vec![crate::chain::types::AuditRecord {
            index: 1,
            timestamp: "2024-01-01T00:00:00Z".into(),
            rule_id: "no-tls".into(),
            severity: "medium".into(),
            target: "server".into(),
            finding: "no tls".into(),
            recommendation: "enable tls".into(),
            hmac: String::new(),
        }];
        let chain = hmac::build_chain(key, "verify-cf", records).unwrap();

        let saved_path = hmac::save_chain(&chain, "verify-cf").unwrap();
        assert!(std::fs::metadata(&saved_path).is_ok());

        let dir = std::env::temp_dir();
        let key_path = dir.join("hermes_vcf_key.bin");
        std::fs::write(&key_path, key).unwrap();

        let (result_chain, valid) =
            verify_chain_file(&saved_path, Some(&key_path.to_string_lossy())).unwrap();
        assert!(valid);
        assert_eq!(result_chain.records.len(), 1);

        let _ = std::fs::remove_file(&saved_path);
        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn test_verify_chain_file_nonexistent() {
        let result = verify_chain_file("/nonexistent/chain.json", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_chain_file_invalid_json() {
        let dir = std::env::temp_dir();
        let path = dir.join("hermes_test_bad_chain.json");
        std::fs::write(&path, "not json").unwrap();
        let result = verify_chain_file(&path.to_string_lossy(), None);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err());
    }
}
