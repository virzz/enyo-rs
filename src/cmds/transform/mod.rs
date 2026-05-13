//! @alias: tf
//! @about: Transform data between JSON, YAML, and TOML

use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use serde_json::Value;

use crate::Action;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Format {
    Json,
    Toml,
    Yaml,
}

impl Format {
    fn from_output_path(path: &str) -> Result<Self> {
        let ext = Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        match ext.as_str() {
            "json" => Ok(Self::Json),
            "toml" => Ok(Self::Toml),
            "yaml" | "yml" => Ok(Self::Yaml),
            _ => Err(anyhow!("Unsupported output format extension: {path}")),
        }
    }
}

#[derive(Parser)]
#[command(name = "transform")]
pub struct Cmd {
    /// Input file path. Reads stdin when omitted or "-".
    #[arg(short = 'i', long = "input")]
    input: Option<String>,

    /// Output file path. Writes stdout when omitted or "-".
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Output JSON.
    #[arg(long = "json")]
    json: bool,

    /// Output TOML.
    #[arg(long = "toml")]
    toml: bool,

    /// Output YAML.
    #[arg(long = "yaml")]
    yaml: bool,

    /// Compact output.
    #[arg(short = 'c', long = "compact")]
    compact: bool,
}

fn detect_output_format(cmd: &Cmd) -> Result<Format> {
    let mut selected = Vec::new();
    if cmd.json {
        selected.push(Format::Json);
    }
    if cmd.toml {
        selected.push(Format::Toml);
    }
    if cmd.yaml {
        selected.push(Format::Yaml);
    }

    match selected.as_slice() {
        [format] => Ok(*format),
        [] => match cmd.output.as_deref() {
            Some(path) if path != "-" => Format::from_output_path(path),
            _ => Ok(Format::Json),
        },
        _ => bail!("Only one output format can be selected"),
    }
}

fn read_input(input: Option<&str>) -> Result<String> {
    match input {
        Some("-") | None => {
            let mut data = String::new();
            io::stdin().read_to_string(&mut data)?;
            Ok(data)
        }
        Some(path) => Ok(fs::read_to_string(path)?),
    }
}

fn parse_data(data: &str) -> Result<Value> {
    serde_json::from_str(data)
        .or_else(|_| toml::from_str(data))
        .or_else(|_| serde_yaml::from_str(data))
        .map_err(|_| anyhow!("Input is not valid JSON, TOML, or YAML"))
}

fn transform_data(data: &str, output: Format, compact: bool) -> Result<String> {
    let value = parse_data(data)?;

    match output {
        Format::Json if compact => Ok(serde_json::to_string(&value)?),
        Format::Json => Ok(serde_json::to_string_pretty(&value)?),
        Format::Toml if compact => Ok(toml::to_string(&value)?.trim_end().to_string()),
        Format::Toml => Ok(toml::to_string_pretty(&value)?.trim_end().to_string()),
        Format::Yaml if compact => Ok(serde_json::to_string(&value)?),
        Format::Yaml => Ok(serde_yaml::to_string(&value)?.trim_end().to_string()),
    }
}

fn write_output(output: Option<&str>, data: &str) -> Result<()> {
    match output {
        Some(path) if path != "-" => fs::write(path, data)?,
        _ => println!("{data}"),
    }

    Ok(())
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        let output_format = detect_output_format(self)?;
        let input = read_input(self.input.as_deref())?;
        let output = transform_data(&input, output_format, self.compact)?;

        write_output(self.output.as_deref(), &output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn json_to_yaml_pretty() {
        let result = transform_data(r#"{"name":"enyo","count":2}"#, Format::Yaml, false).unwrap();

        assert!(result.contains("name: enyo"));
        assert!(result.contains("count: 2"));
    }

    #[test]
    fn yaml_to_json_compact() {
        let result = transform_data("name: enyo\ncount: 2\n", Format::Json, true).unwrap();

        assert_eq!(result, r#"{"count":2,"name":"enyo"}"#);
    }

    #[test]
    fn toml_to_json_pretty() {
        let result = transform_data("name = \"enyo\"\ncount = 2\n", Format::Json, false).unwrap();

        assert!(result.contains("\"name\": \"enyo\""));
        assert!(result.contains("\"count\": 2"));
    }

    #[test]
    fn json_to_yaml_compact() {
        let result = transform_data(r#"{"name":"enyo","count":2}"#, Format::Yaml, true).unwrap();

        assert_eq!(result, r#"{"count":2,"name":"enyo"}"#);
    }

    #[test]
    fn infer_format_from_output_extension() {
        assert_eq!(
            Format::from_output_path("config.toml").unwrap(),
            Format::Toml
        );
        assert_eq!(
            Format::from_output_path("config.yaml").unwrap(),
            Format::Yaml
        );
        assert_eq!(
            Format::from_output_path("config.json").unwrap(),
            Format::Json
        );
    }

    #[tokio::test]
    async fn output_extension_controls_format_when_flag_is_absent() {
        let temp_dir = TempDir::new().unwrap();
        let input = temp_dir.path().join("input.json");
        let output = temp_dir.path().join("output.toml");
        fs::write(&input, r#"{"name":"enyo","count":2}"#).unwrap();

        Cmd {
            input: Some(input.to_string_lossy().to_string()),
            output: Some(output.to_string_lossy().to_string()),
            json: false,
            toml: false,
            yaml: false,
            compact: false,
        }
        .execute()
        .await
        .unwrap();

        let result = fs::read_to_string(output).unwrap();
        assert!(result.contains("name = \"enyo\""));
        assert!(result.contains("count = 2"));
    }

    #[test]
    fn rejects_multiple_output_format_flags() {
        let cmd = Cmd {
            input: None,
            output: None,
            json: true,
            toml: true,
            yaml: false,
            compact: false,
        };

        assert!(detect_output_format(&cmd)
            .unwrap_err()
            .to_string()
            .contains("Only one output format"));
    }
}
