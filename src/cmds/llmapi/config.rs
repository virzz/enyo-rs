use std::{env, fs, path::Path, str::FromStr};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server: String,
    pub base_url: String,
    pub provider: Provider,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Provider {
    #[value(name = "openai-compatible")]
    OpenAiCompatible,
    #[value(name = "openai-chat")]
    OpenAiChat,
    #[value(name = "openai-responses")]
    OpenAiResponses,
    #[value(name = "claude")]
    Claude,
    #[value(name = "gemini")]
    Gemini,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("parse yaml config: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("parse toml config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported config extension: {0}")]
    UnsupportedExtension(String),
    #[error("unknown provider: {0}")]
    UnknownProvider(String),
    #[error("expand environment variable {name}: {source}")]
    EnvVar {
        name: String,
        #[source]
        source: env::VarError,
    },
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    server: String,
    base_url: String,
    provider: String,
    api_key: Option<String>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let body = fs::read_to_string(path)?;
        let raw = match extension(path).as_deref() {
            Some("yaml" | "yml") => serde_yaml::from_str::<RawConfig>(&body)?,
            Some("toml") => toml::from_str::<RawConfig>(&body)?,
            Some(ext) => return Err(ConfigError::UnsupportedExtension(ext.to_string())),
            None => return Err(ConfigError::UnsupportedExtension(String::new())),
        };

        Ok(Self {
            server: raw.server,
            base_url: raw.base_url.trim_end_matches('/').to_string(),
            provider: Provider::from_str(&raw.provider)?,
            api_key: raw.api_key.map(expand_env).transpose()?,
        })
    }
}

impl FromStr for Provider {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "openai-compatible" => Ok(Self::OpenAiCompatible),
            "openai-chat" => Ok(Self::OpenAiChat),
            "openai-responses" => Ok(Self::OpenAiResponses),
            "claude" => Ok(Self::Claude),
            "gemini" => Ok(Self::Gemini),
            other => Err(ConfigError::UnknownProvider(other.to_string())),
        }
    }
}

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

fn expand_env(value: String) -> Result<String, ConfigError> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value.as_str();

    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            output.push_str(&rest[start..]);
            return Ok(output);
        };

        let name = &after_start[..end];
        let replacement = env::var(name).map_err(|source| ConfigError::EnvVar {
            name: name.to_string(),
            source,
        })?;
        output.push_str(&replacement);
        rest = &after_start[end + 1..];
    }

    output.push_str(rest);
    Ok(output)
}
