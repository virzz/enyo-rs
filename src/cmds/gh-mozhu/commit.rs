//! @about: Git commit message formatter with Conventional Commits

use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::process::Command;

use crate::Action;

#[derive(Parser)]
#[command(name = "gh-mozhu")]
#[command(bin_name = "gh-mozhu")]
#[command(author, version = env!("CARGO_PKG_VERSION"), about = "Git commit message formatter", long_about = None)]
pub struct Cmd {
    /// 项目初始化
    #[arg(long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    init: bool,

    /// 添加新特性
    #[arg(long = "feat")]
    feature: Option<String>,

    /// 修复Bug
    #[arg(long = "fix")]
    fix: Option<String>,

    /// 仅仅修改文档
    #[arg(long = "docs")]
    docs: Option<String>,

    /// 仅仅修改了空格、格式缩进、逗号等
    #[arg(long = "style", alias = "sty")]
    style: Option<String>,

    /// 代码重构，没有加新功能或者修复bug
    #[arg(long = "refactor", alias = "refa")]
    refactor: Option<String>,

    /// 优化相关，比如提升性能、体验
    #[arg(long = "perf")]
    perf: Option<String>,

    /// 单元测试的添加或修复
    #[arg(long = "test")]
    test: Option<String>,

    /// 改变构建流程、或者增加依赖库、工具等
    #[arg(long = "chore")]
    chore: Option<String>,

    /// 回滚到上一个版本
    #[arg(long = "revert", alias = "rev")]
    revert: Option<String>,

    /// Message Body
    #[arg(long = "body")]
    body: Option<String>,

    /// With PR number
    #[arg(long = "pr")]
    pr: Vec<i64>,

    /// With closes issue number
    #[arg(long = "closes")]
    closes: Vec<i64>,

    /// With breaking changes
    #[arg(long = "breaks")]
    breaks: Vec<String>,

    /// Execute git commit
    #[arg(short = 'c', long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    commit: bool,

    /// Hide emoji icon in commit message
    #[arg(long = "hide-icon", action = clap::ArgAction::SetTrue, default_value_t = false)]
    hide_icon: bool,

    /// Message Subject
    #[arg(help = "Message Subject")]
    message: Option<Vec<String>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CommitType {
    Init,     // 初始化
    Feature,  // 新增功能
    Fix,      // Bug修复
    Docs,     // 编辑文档
    Refactor, // 重构
    Style,    // 样式
    Perf,     // 性能优化
    Test,     // 单元测试的添加或修复
    Chore,    // 构建工具的修改
    Revert,   // 回滚
}

impl CommitType {
    fn icon(&self) -> &str {
        match self {
            CommitType::Init => "🎉",
            CommitType::Feature => "✨",
            CommitType::Fix => "🐞",
            CommitType::Docs => "📃",
            CommitType::Style => "🌈",
            CommitType::Refactor => "🦄",
            CommitType::Perf => "🚀",
            CommitType::Test => "🧪",
            CommitType::Chore => "🔧",
            CommitType::Revert => "↩",
        }
    }

    fn name(&self) -> &str {
        match self {
            CommitType::Init => "Initializing",
            CommitType::Feature => "feat",
            CommitType::Fix => "fix",
            CommitType::Docs => "docs",
            CommitType::Style => "style",
            CommitType::Refactor => "refactor",
            CommitType::Perf => "perf",
            CommitType::Test => "test",
            CommitType::Chore => "chore",
            CommitType::Revert => "revert",
        }
    }
}

// Commit message format:
// [ICON] [TYPES]([SCOPES]): [SUBJECT] (#pr)
// <\n>
// [BODY]
// <\n>
// [FOOTER]

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        let mut header = String::new();

        if self.init {
            header.push_str(&format!("{} Initializing", CommitType::Init.icon()));
        } else {
            let commit_types: Vec<(Option<&String>, CommitType)> = vec![
                (self.feature.as_ref(), CommitType::Feature),
                (self.fix.as_ref(), CommitType::Fix),
                (self.docs.as_ref(), CommitType::Docs),
                (self.style.as_ref(), CommitType::Style),
                (self.refactor.as_ref(), CommitType::Refactor),
                (self.perf.as_ref(), CommitType::Perf),
                (self.test.as_ref(), CommitType::Test),
                (self.chore.as_ref(), CommitType::Chore),
                (self.revert.as_ref(), CommitType::Revert),
            ];

            for (action, ct) in commit_types {
                if let Some(scope) = action {
                    if self.hide_icon {
                        header.push_str(&format!("{}({})", ct.name(), scope));
                    } else {
                        header.push_str(&format!("{}{}({})", ct.icon(), ct.name(), scope));
                    }
                }
            }

            if let Some(message) = &self.message {
                header.push_str(&format!(": {} ", message.join(" ")));
            }

            for pr in &self.pr {
                header.push_str(&format!("(#{})", pr));
            }
        }

        let body = self.body.as_deref().unwrap_or("");

        let mut footer: Vec<String> = vec![];

        if !self.closes.is_empty() {
            footer.push(format!(
                "Closes: {}",
                self.closes
                    .iter()
                    .map(|&num| format!("#{}", num))
                    .collect::<Vec<String>>()
                    .join(", ")
            ));
        }

        if !self.breaks.is_empty() {
            footer.push(format!("Breaks: {}", self.breaks.join(", ")));
        }

        let result = if !footer.is_empty() {
            if !body.is_empty() {
                format!("{}\n\n{}\n\n{}", header, body, footer.join("\n"))
            } else {
                format!("{}\n\n\n\n{}", header, footer.join("\n"))
            }
        } else if !body.is_empty() {
            format!("{}\n\n{}", header, body)
        } else {
            header
        };

        if self.commit {
            let output = Command::new("git")
                .args(["commit", "-m", &result])
                .output()?;

            if output.status.success() {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            } else {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
            }
        } else {
            println!("{}", result);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_commit_feature() {
        let cmd = Cmd::parse_from(["gh-mozhu", "--feat", "core", "add new feature"]);
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_commit_fix_with_pr() {
        let cmd = Cmd::parse_from(["gh-mozhu", "--fix", "api", "--pr", "123", "fix bug"]);
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_commit_init() {
        let cmd = Cmd::parse_from(["gh-mozhu", "--init"]);
        cmd.execute().await.unwrap();
    }
}
