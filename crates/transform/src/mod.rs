//! @alias: tf
//! @about: Transform data between JSON, YAML, and TOML

use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use serde_json::{Map, Value};

use enyo_core::Action;

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

    /// Wrap a top-level list in `items` when outputting TOML.
    #[arg(long = "force")]
    force: bool,
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

fn transform_data(data: &str, output: Format, compact: bool, force: bool) -> Result<String> {
    let mut value = parse_data(data)?;
    if output == Format::Toml && value.is_array() {
        if !force {
            bail!("TOML requires a top-level mapping; use --force to wrap this list in an 'items' key");
        }
        let mut root = Map::new();
        root.insert("items".to_string(), value);
        value = Value::Object(root);
    }
    if output == Format::Toml && !value.is_object() {
        bail!("TOML requires a top-level mapping");
    }

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

impl Action for Cmd {
    fn execute(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        std::future::ready(self.execute_sync())
    }
}

impl Cmd {
    fn execute_sync(&self) -> Result<()> {
        let output_format = detect_output_format(self)?;
        let input = read_input(self.input.as_deref())?;
        let output = transform_data(&input, output_format, self.compact, self.force)?;

        write_output(self.output.as_deref(), &output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn json_to_yaml_pretty() {
        let result =
            transform_data(r#"{"name":"enyo","count":2}"#, Format::Yaml, false, false).unwrap();

        assert!(result.contains("name: enyo"));
        assert!(result.contains("count: 2"));
    }

    #[test]
    fn yaml_to_json_compact() {
        let result = transform_data("name: enyo\ncount: 2\n", Format::Json, true, false).unwrap();

        assert_eq!(result, r#"{"count":2,"name":"enyo"}"#);
    }

    #[test]
    fn yaml_sequence_to_toml_requires_force() {
        let error = transform_data("- name: enyo\n- name: codex\n", Format::Toml, false, false)
            .unwrap_err();

        assert!(error.to_string().contains("use --force"));
    }

    #[test]
    fn yaml_sequence_to_toml_wraps_items_with_force() {
        let result =
            transform_data("- name: enyo\n- name: codex\n", Format::Toml, false, true).unwrap();
        let parsed: toml::Value = toml::from_str(&result).unwrap();

        assert_eq!(parsed["items"][0]["name"].as_str(), Some("enyo"));
        assert_eq!(parsed["items"][1]["name"].as_str(), Some("codex"));
    }

    #[test]
    fn toml_to_json_pretty() {
        let result =
            transform_data("name = \"enyo\"\ncount = 2\n", Format::Json, false, false).unwrap();

        assert!(result.contains("\"name\": \"enyo\""));
        assert!(result.contains("\"count\": 2"));
    }

    #[test]
    fn json_to_yaml_compact() {
        let result =
            transform_data(r#"{"name":"enyo","count":2}"#, Format::Yaml, true, false).unwrap();

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

    #[test]
    fn parses_force_flag() {
        let cmd = Cmd::try_parse_from([
            "transform",
            "-i",
            "config.yaml",
            "--toml",
            "-o",
            "config.toml",
            "--force",
        ])
        .unwrap();

        assert!(cmd.force);
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
            force: false,
        }
        .execute()
        .await
        .unwrap();

        let result = fs::read_to_string(output).unwrap();
        assert!(result.contains("name = \"enyo\""));
        assert!(result.contains("count = 2"));
    }

    #[tokio::test]
    async fn yaml_list_file_to_toml_file_requires_force() {
        let temp_dir = TempDir::new().unwrap();
        let input = temp_dir.path().join("config.yaml");
        let output = temp_dir.path().join("config.toml");
        fs::write(&input, "- name: enyo\n- name: codex\n").unwrap();

        Cmd {
            input: Some(input.to_string_lossy().to_string()),
            output: Some(output.to_string_lossy().to_string()),
            json: false,
            toml: true,
            yaml: false,
            compact: false,
            force: false,
        }
        .execute()
        .await
        .unwrap_err();

        assert!(!output.exists());

        Cmd {
            input: Some(input.to_string_lossy().to_string()),
            output: Some(output.to_string_lossy().to_string()),
            json: false,
            toml: true,
            yaml: false,
            compact: false,
            force: true,
        }
        .execute()
        .await
        .unwrap();

        let result = fs::read_to_string(output).unwrap();
        let parsed: toml::Value = toml::from_str(&result).unwrap();
        assert_eq!(parsed["items"][0]["name"].as_str(), Some("enyo"));
        assert_eq!(parsed["items"][1]["name"].as_str(), Some("codex"));
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
            force: false,
        };

        assert!(detect_output_format(&cmd)
            .unwrap_err()
            .to_string()
            .contains("Only one output format"));
    }
}
