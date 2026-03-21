use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// 命令配置
#[derive(Debug, Clone)]
struct CmdConfig {
    mod_name: String,     // 模块名 (目录名)
    cmd_name: String,     // 命令名 (PascalCase)
    aliases: Vec<String>, // 别名
    about: String,        // 描述
}

/// 检查模块是否导出了 `pub struct Cmd`
fn has_cmd_struct(mod_rs_path: &Path) -> bool {
    let content = fs::read_to_string(mod_rs_path).unwrap_or_default();
    // 检查是否有 `pub struct Cmd` 声明
    content.contains("pub struct Cmd")
}

/// 从 mod.rs 文件解析命令配置
fn parse_cmd_config(dir_name: &str, mod_rs_path: &Path) -> Option<CmdConfig> {
    // 跳过不导出 Cmd 结构体的模块
    if !has_cmd_struct(mod_rs_path) {
        return None;
    }
    // 跳过包含特殊字符的目录名（如 gh-mozhu）
    if !dir_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }

    let file = File::open(mod_rs_path).ok()?;
    let reader = BufReader::new(file);

    let mut aliases = Vec::new();
    let mut about = String::new();

    // 解析注释中的配置
    // 格式: //! @alias: ts
    //       //! @about: Print or parse timestamps
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

    // 将 snake_case 转为 PascalCase
    let cmd_name = dir_name
        .split('_')
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().chain(c).collect(),
            }
        })
        .collect::<String>();

    // 如果没有描述，使用默认值
    if about.is_empty() {
        about = format!("{cmd_name} command");
    }

    Some(CmdConfig {
        mod_name: dir_name.to_string(),
        cmd_name,
        aliases,
        about,
    })
}

/// 扫描 cmds 目录，获取所有子命令配置
fn scan_cmds_dir(modules_dir: &Path) -> Vec<CmdConfig> {
    let mut configs = Vec::new();

    if let Ok(entries) = fs::read_dir(modules_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            // 只处理目录
            if !path.is_dir() {
                continue;
            }
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // 检查是否有 mod.rs
            let mod_rs = path.join("mod.rs");
            if mod_rs.exists() {
                if let Some(config) = parse_cmd_config(dir_name, &mod_rs) {
                    configs.push(config);
                }
            }
        }
    }
    // 按名称排序
    configs.sort_by(|a, b| a.mod_name.cmp(&b.mod_name));
    configs
}

/// 生成 mod 声明
fn generate_mod_declarations(configs: &[CmdConfig]) -> String {
    configs
        .iter()
        .map(|c| format!("pub mod {};", c.mod_name))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 生成 enum 变体
fn generate_enum_variants(configs: &[CmdConfig]) -> String {
    configs
        .iter()
        .map(|c| {
            let mut attrs = Vec::new();

            // 添加别名
            for alias in &c.aliases {
                attrs.push(format!("alias = \"{alias}\""));
            }

            let clap_attr = if attrs.is_empty() {
                String::new()
            } else {
                format!("    #[clap({})]\n", attrs.join(", "))
            };

            format!(
                "    /// {}\n{}    {}({}::Cmd),",
                c.about, clap_attr, c.cmd_name, c.mod_name
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// 生成 match arms
fn generate_match_arms(configs: &[CmdConfig]) -> String {
    configs
        .iter()
        .map(|c| {
            format!(
                "            Command::{}(c) => c.execute().await,",
                c.cmd_name
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn main() {
    // 输出版本信息
    println!(
        "cargo:rustc-env=CARGO_PKG_VERSION={}",
        env!("CARGO_PKG_VERSION")
    );

    // 获取项目根目录
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cmds_dir = Path::new(&manifest_dir).join("src/cmds");
    let mod_rs_path = cmds_dir.join("mod.rs");

    // let bin_dir = Path::new(&manifest_dir).join("src/bin");

    // 当 enyo 目录变化时重新运行
    println!("cargo:rerun-if-changed={}", cmds_dir.to_string_lossy());

    // 扫描子命令
    let cmds = scan_cmds_dir(&cmds_dir);

    // 为每个子命令目录设置重新构建触发
    for cmd in &cmds {
        println!("cargo:rerun-if-changed=src/cmds/{}/mod.rs", cmd.mod_name);
    }

    // 生成代码
    let mod_declarations = generate_mod_declarations(&cmds);
    let enum_variants = generate_enum_variants(&cmds);
    let match_arms = generate_match_arms(&cmds);

    let generated_code = format!(
        r#"//! 此文件由 build.rs 自动生成，请勿手动修改
//! Auto-generated by build.rs, DO NOT EDIT

use anyhow::Result;
use clap::Subcommand;
use clap_complete::aot::Shell;

{mod_declarations}

use crate::{{core::external,Action}};

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

    // 读取现有文件内容（如果存在）
    let existing_content = fs::read_to_string(&mod_rs_path).unwrap_or_default();

    // 只有内容变化时才写入，避免不必要的重新编译
    if existing_content != generated_code {
        let mut f = File::create(&mod_rs_path).unwrap();
        f.write_all(generated_code.as_bytes()).unwrap();
        println!("cargo:warning=Generated src/cmds/mod.rs");
    }
}
