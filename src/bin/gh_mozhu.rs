//! gh-mozhu - GitHub CLI extension for commit message formatting
//!
//! Usage: gh mozhu --feat core "add new feature"

use clap::Parser;
use enyo::CmdExecute;

// 手动导入 gh-mozhu 模块（因为目录名包含连字符）
#[path = "../cmds/gh-mozhu/mod.rs"]
mod gh_mozhu;

use gh_mozhu::Cmd;

#[tokio::main]
async fn main() {
    match Cmd::try_parse() {
        Ok(cmd) => {
            if let Err(e) = cmd.execute().await {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
