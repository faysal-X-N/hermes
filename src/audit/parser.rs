use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(rename = "mcpServers")]
    pub mcp_servers: HashMap<String, ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub command: Option<String>,

    #[serde(default)]
    pub args: Option<Vec<String>>,

    #[serde(default)]
    pub cmd: Option<String>,

    #[serde(default)]
    pub run: Option<String>,

    #[serde(default)]
    pub exec: Option<String>,

    #[serde(default)]
    pub env: Option<HashMap<String, String>>,

    #[serde(default, alias = "apiKey")]
    pub api_key: Option<String>,

    #[serde(default)]
    pub token: Option<String>,

    #[serde(default, alias = "accessToken")]
    pub access_token: Option<String>,

    #[serde(default)]
    pub secret: Option<String>,

    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub passwd: Option<String>,

    #[serde(default)]
    pub pwd: Option<String>,

    #[serde(default)]
    pub url: Option<String>,

    #[serde(default)]
    pub host: Option<String>,

    #[serde(default)]
    pub bind: Option<String>,

    #[serde(default, alias = "autoApprove")]
    pub auto_approve: Option<Vec<String>>,

    #[serde(default, alias = "allowedTools")]
    pub allowed_tools: Option<Vec<String>>,

    #[serde(default)]
    pub allow: Option<Vec<String>>,

    #[serde(default)]
    pub auth: Option<String>,

    #[serde(default, alias = "authorization")]
    pub authorization: Option<String>,

    #[serde(default)]
    pub timeout: Option<u64>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub transport: Option<String>,

    #[serde(default)]
    pub tools: Option<HashMap<String, serde_json::Value>>,

    #[serde(default)]
    pub disabled: Option<bool>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl ServerConfig {
    pub fn get_command(&self) -> Option<&str> {
        self.command
            .as_deref()
            .or_else(|| self.cmd.as_deref())
            .or_else(|| self.run.as_deref())
            .or_else(|| self.exec.as_deref())
    }

    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn get_all_args(&self) -> Vec<&str> {
        let mut all = Vec::new();
        if let Some(ref args) = self.args {
            for a in args {
                all.push(a.as_str());
            }
        }
        // If command field is set, first arg might be the command itself
        if let Some(ref cmd) = self.command {
            if all.is_empty() {
                all.push(cmd.as_str());
            }
        }
        all
    }

    pub fn get_credential(&self) -> Option<&str> {
        self.api_key
            .as_deref()
            .or_else(|| self.token.as_deref())
            .or_else(|| self.access_token.as_deref())
            .or_else(|| self.secret.as_deref())
    }

    pub fn get_password(&self) -> Option<&str> {
        self.password
            .as_deref()
            .or_else(|| self.passwd.as_deref())
            .or_else(|| self.pwd.as_deref())
    }

    pub fn has_url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn is_env_var_ref(value: &str) -> bool {
        value.starts_with("${") && value.ends_with('}')
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedConfig {
    pub file_path: String,
    pub servers: HashMap<String, ServerConfig>,
    pub parse_errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_mcp_json() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@scope/server"],
                    "env": { "API_KEY": "${MY_KEY}" },
                    "allowedTools": ["read", "write"]
                }
            }
        }"#;
        let config: McpConfig = serde_json::from_str(json).unwrap();
        let server = &config.mcp_servers["filesystem"];
        assert_eq!(server.command.as_deref(), Some("npx"));
        assert_eq!(server.allowed_tools.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_camel_case_aliases() {
        let json = r#"{
            "mcpServers": {
                "s": {
                    "apiKey": "secret123",
                    "accessToken": "tok456",
                    "autoApprove": ["*"],
                    "allowedTools": ["read"]
                }
            }
        }"#;
        let config: McpConfig = serde_json::from_str(json).unwrap();
        let server = &config.mcp_servers["s"];
        assert_eq!(server.api_key.as_deref(), Some("secret123"));
        assert_eq!(server.access_token.as_deref(), Some("tok456"));
        assert_eq!(server.auto_approve.as_ref().unwrap().len(), 1);
        assert_eq!(server.allowed_tools.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_get_command_field_aliases() {
        let mut server = ServerConfig {
            cmd: Some("node".into()),
            ..Default::default()
        };
        assert_eq!(server.get_command(), Some("node"));

        server.cmd = None;
        server.run = Some("python".into());
        assert_eq!(server.get_command(), Some("python"));

        server.run = None;
        server.exec = Some("java".into());
        assert_eq!(server.get_command(), Some("java"));
    }

    #[test]
    fn test_get_credential_field_aliases() {
        let server = ServerConfig {
            api_key: Some("key".into()),
            ..Default::default()
        };
        assert_eq!(server.get_credential(), Some("key"));

        let server = ServerConfig {
            token: Some("tok".into()),
            ..Default::default()
        };
        assert_eq!(server.get_credential(), Some("tok"));

        let server = ServerConfig {
            access_token: Some("acc".into()),
            ..Default::default()
        };
        assert_eq!(server.get_credential(), Some("acc"));

        let server = ServerConfig {
            secret: Some("sec".into()),
            ..Default::default()
        };
        assert_eq!(server.get_credential(), Some("sec"));
    }

    #[test]
    fn test_get_password_field_aliases() {
        let server = ServerConfig {
            password: Some("pwd1".into()),
            ..Default::default()
        };
        assert_eq!(server.get_password(), Some("pwd1"));

        let server = ServerConfig {
            passwd: Some("pwd2".into()),
            ..Default::default()
        };
        assert_eq!(server.get_password(), Some("pwd2"));

        let server = ServerConfig {
            pwd: Some("pwd3".into()),
            ..Default::default()
        };
        assert_eq!(server.get_password(), Some("pwd3"));
    }

    #[test]
    fn test_is_env_var_ref() {
        assert!(ServerConfig::is_env_var_ref("${MY_KEY}"));
        assert!(ServerConfig::is_env_var_ref("${SECRET_TOKEN}"));
        assert!(!ServerConfig::is_env_var_ref("sk-abc"));
        assert!(!ServerConfig::is_env_var_ref("${incomplete"));
        assert!(!ServerConfig::is_env_var_ref("not$var"));
    }

    #[test]
    fn test_host_and_bind_fields() {
        let server = ServerConfig {
            host: Some("0.0.0.0".into()),
            bind: Some("127.0.0.1".into()),
            ..Default::default()
        };
        assert_eq!(server.host.as_deref(), Some("0.0.0.0"));
        assert_eq!(server.bind.as_deref(), Some("127.0.0.1"));
    }

    impl Default for ServerConfig {
        fn default() -> Self {
            Self {
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
    }
}
