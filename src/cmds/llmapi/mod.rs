//! @about: LLM API proxy

pub mod adapters;
pub mod auth;
pub mod config;
pub mod log;
pub mod model;
pub mod protocol;
pub mod proxy;
pub mod server;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

use crate::Action;

use config::{Config, Provider};

#[derive(Debug, Parser)]
#[command(name = "llmapi")]
pub struct Cmd {
    /// Config file path
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Server listen address
    #[arg(long)]
    server: Option<String>,

    /// Upstream API base URL
    #[arg(long)]
    base_url: Option<String>,

    /// Upstream provider: openai-compatible, openai-chat, openai-responses, claude, gemini
    #[arg(long)]
    provider: Option<Provider>,

    /// Upstream API key. Overrides client request keys.
    #[arg(long)]
    api_key: Option<String>,
}

impl Cmd {
    fn default_config_path() -> PathBuf {
        dirs::home_dir()
            .map(|home| home.join(".config/enyo/llmapi.toml"))
            .unwrap_or_else(|| PathBuf::from(".config/enyo/llmapi.toml"))
    }

    fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(Self::default_config_path)
    }

    fn load_config(&self) -> Result<Config> {
        let config_path = self.config_path();
        let mut config = Config::load(&config_path)
            .with_context(|| format!("load config {}", config_path.display()))?;

        if let Some(server) = &self.server {
            config.server = server.clone();
        }
        if let Some(base_url) = &self.base_url {
            config.base_url = base_url.trim_end_matches('/').to_string();
        }
        if let Some(provider) = self.provider {
            config.provider = provider;
        }
        if let Some(api_key) = &self.api_key {
            config.api_key = Some(api_key.clone());
        }

        Ok(config)
    }
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        let config = self.load_config()?;
        let addr: SocketAddr = config
            .server
            .parse()
            .context("parse server listen address")?;

        server::serve(addr, config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn default_config_path_points_to_enyo_llmapi_toml() {
        let path = Cmd::default_config_path();

        assert!(path.ends_with(".config/enyo/llmapi.toml"));
    }

    #[test]
    fn cli_args_override_file_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("llmapi.toml");
        fs::write(
            &path,
            r#"
server = "127.0.0.1:8080"
base_url = "https://example.test/"
provider = "openai-chat"
api_key = "sk-file"
"#,
        )
        .unwrap();

        let cmd = Cmd {
            config: Some(path),
            server: Some("127.0.0.1:9090".to_string()),
            base_url: Some("https://api.openai.com/".to_string()),
            provider: Some(Provider::OpenAiResponses),
            api_key: Some("sk-cli".to_string()),
        };

        let config = cmd.load_config().unwrap();

        assert_eq!(config.server, "127.0.0.1:9090");
        assert_eq!(config.base_url, "https://api.openai.com");
        assert_eq!(config.provider, Provider::OpenAiResponses);
        assert_eq!(config.api_key.as_deref(), Some("sk-cli"));
    }
}
