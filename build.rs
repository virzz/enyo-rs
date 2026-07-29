use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone)]
struct CmdConfig {
    mod_name: String,
    crate_name: String,
    cmd_name: String,
    type_name: String,
    execute_method: String,
    aliases: Vec<String>,
    about: String,
}

fn is_rust_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn command_type_name(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

fn has_cmd_struct(mod_rs_path: &Path) -> bool {
    let content = fs::read_to_string(mod_rs_path).unwrap_or_default();
    content.contains("pub struct Cmd")
}

fn parse_cmd_config(dir_name: &str, mod_rs_path: &Path) -> Option<CmdConfig> {
    if !has_cmd_struct(mod_rs_path) {
        return None;
    }
    if !is_rust_identifier(dir_name) {
        return None;
    }

    let file = File::open(mod_rs_path).ok()?;
    let reader = BufReader::new(file);

    let mut aliases = Vec::new();
    let mut about = String::new();

    for line in reader.lines() {
        let line = line.ok()?;
        let trimmed = line.trim();

        if trimmed.starts_with("//! @alias:") {
            let alias = trimmed.trim_start_matches("//! @alias:").trim();
            if !alias.is_empty() {
                aliases.push(alias.to_string());
            }
        } else if trimmed.starts_with("//! @about:") {
            about = trimmed.trim_start_matches("//! @about:").trim().to_string();
        }
    }

    let cmd_name = command_type_name(dir_name);

    if about.is_empty() {
        about = format!("{cmd_name} command");
    }

    Some(CmdConfig {
        mod_name: dir_name.to_string(),
        crate_name: format!("enyo_cmd_{dir_name}"),
        cmd_name,
        type_name: "Cmd".to_string(),
        execute_method: "execute".to_string(),
        aliases,
        about,
    })
}

fn external_cmds(manifest_path: &Path) -> Vec<CmdConfig> {
    let manifest_text = fs::read_to_string(manifest_path).unwrap_or_else(|error| {
        panic!("read {}: {error}", manifest_path.display());
    });
    let manifest: toml::Value = toml::from_str(&manifest_text).unwrap_or_else(|error| {
        panic!("parse {}: {error}", manifest_path.display());
    });
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("root Cargo.toml must contain [dependencies]");
    let Some(commands) = manifest
        .get("package")
        .and_then(|value| value.get("metadata"))
        .and_then(|value| value.get("enyo"))
        .and_then(|value| value.get("external-commands"))
        .and_then(toml::Value::as_table)
    else {
        return Vec::new();
    };

    commands
        .iter()
        .map(|(mod_name, value)| {
            let config = value
                .as_table()
                .unwrap_or_else(|| panic!("external command `{mod_name}` must be a table"));
            let crate_name = config
                .get("crate")
                .and_then(toml::Value::as_str)
                .unwrap_or(mod_name);
            let type_name = config
                .get("type")
                .and_then(toml::Value::as_str)
                .unwrap_or("Cmd");
            let execute_method = config
                .get("execute")
                .and_then(toml::Value::as_str)
                .unwrap_or("execute");
            for (field, identifier) in [
                ("command", mod_name.as_str()),
                ("crate", crate_name),
                ("type", type_name),
                ("execute", execute_method),
            ] {
                assert!(
                    is_rust_identifier(identifier),
                    "external command `{mod_name}` has invalid Rust identifier in `{field}`"
                );
            }
            assert!(
                dependencies.contains_key(crate_name),
                "external command `{mod_name}` references missing dependency `{crate_name}`"
            );
            let aliases = config
                .get("aliases")
                .and_then(toml::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .map(|value| {
                            value.as_str().unwrap_or_else(|| {
                                panic!("external command `{mod_name}` aliases must be strings")
                            })
                        })
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let cmd_name = config
                .get("name")
                .and_then(toml::Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| command_type_name(mod_name));
            assert!(
                is_rust_identifier(&cmd_name),
                "external command `{mod_name}` has invalid enum variant name `{cmd_name}`"
            );
            let about = config
                .get("about")
                .and_then(toml::Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("{cmd_name} command"));

            CmdConfig {
                mod_name: mod_name.to_string(),
                crate_name: crate_name.to_string(),
                cmd_name,
                type_name: type_name.to_string(),
                execute_method: execute_method.to_string(),
                aliases,
                about,
            }
        })
        .collect()
}

fn scan_cmds_dir(modules_dir: &Path) -> Vec<CmdConfig> {
    let mut configs = Vec::new();

    if let Ok(entries) = fs::read_dir(modules_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let mod_rs = path.join("src/mod.rs");
            if mod_rs.exists() {
                if let Some(config) = parse_cmd_config(dir_name, &mod_rs) {
                    configs.push(config);
                }
            }
        }
    }

    configs.sort_by(|a, b| a.mod_name.cmp(&b.mod_name));
    configs
}

fn generate_crate_imports(configs: &[CmdConfig]) -> String {
    configs
        .iter()
        .filter(|config| config.crate_name != config.mod_name)
        .map(|config| format!("use {} as {};", config.crate_name, config.mod_name))
        .collect::<Vec<_>>()
        .join("\n")
}

fn generate_enum_variants(configs: &[CmdConfig]) -> String {
    configs
        .iter()
        .map(|c| {
            let attrs = c
                .aliases
                .iter()
                .map(|alias| format!("alias = \"{alias}\""))
                .collect::<Vec<_>>();

            let clap_attr = if attrs.is_empty() {
                String::new()
            } else {
                format!("    #[clap({})]\n", attrs.join(", "))
            };

            format!(
                "    /// {}\n{}    {}({}::{}),",
                c.about, clap_attr, c.cmd_name, c.mod_name, c.type_name
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn generate_match_arms(configs: &[CmdConfig]) -> String {
    configs
        .iter()
        .map(|c| {
            format!(
                "            Command::{}(c) => c.{}().await,",
                c.cmd_name, c.execute_method
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn main() {
    println!(
        "cargo:rustc-env=CARGO_PKG_VERSION={}",
        env!("CARGO_PKG_VERSION")
    );

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_dir = Path::new(&manifest_dir);
    let manifest_path = workspace_dir.join("Cargo.toml");
    let cmds_dir = workspace_dir.join("crates");
    let mod_rs_path = workspace_dir.join("src/cmds.rs");

    println!("cargo:rerun-if-changed={}", cmds_dir.to_string_lossy());
    println!("cargo:rerun-if-changed={}", manifest_path.to_string_lossy());

    let mut cmds = scan_cmds_dir(&cmds_dir);
    for cmd in &cmds {
        println!(
            "cargo:rerun-if-changed={}/src/mod.rs",
            cmds_dir.join(&cmd.mod_name).to_string_lossy()
        );
    }
    cmds.extend(external_cmds(&manifest_path));
    cmds.sort_by(|left, right| left.mod_name.cmp(&right.mod_name));
    assert!(
        cmds.windows(2)
            .all(|commands| commands[0].mod_name != commands[1].mod_name),
        "local and external commands must have unique names"
    );

    let crate_imports = generate_crate_imports(&cmds);
    let enum_variants = generate_enum_variants(&cmds);
    let match_arms = generate_match_arms(&cmds);

    let generated_code = format!(
        r#"//! 此文件由 build.rs 自动生成，请勿手动修改
//! Auto-generated by build.rs, DO NOT EDIT

use anyhow::Result;
use clap::Subcommand;
use clap_complete::aot::Shell;

{crate_imports}

use enyo_core::{{core::external, Action}};

#[derive(Subcommand)]
pub enum Command {{
    /// External command
    #[clap(external_subcommand)]
    External(Vec<String>),

    /// Shell completion scripts
    #[clap(alias = "comp")]
    Completion {{
        #[arg(help = "shell type")]
        shell: Option<Shell>,
    }},

{enum_variants}
}}

impl Command {{
    pub async fn invoke(&self) -> Result<()> {{
        match self {{
            Command::External(args) => external(args),
{match_arms}
            _ => Err(anyhow::anyhow!("Unknown command")),
        }}
    }}
}}
"#
    );

    let existing_content = fs::read_to_string(&mod_rs_path).unwrap_or_default();
    if existing_content != generated_code {
        let mut f = File::create(&mod_rs_path).unwrap();
        f.write_all(generated_code.as_bytes()).unwrap();
        println!("cargo:warning=Generated src/cmds.rs");
    }
}
