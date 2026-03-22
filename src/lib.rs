use std::io;

use clap::{crate_authors, ArgAction::SetTrue, CommandFactory, Parser};
use clap_complete::{generate, Shell};
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub(crate) mod cmds;
pub mod core;

use core::Action;

#[derive(Parser)]
#[command(author=crate_authors!("\n"), version= env!("CARGO_PKG_VERSION"), about, disable_help_subcommand=true, long_about = None)]
pub struct App {
    #[arg(short, long, action = SetTrue, default_value_t = false, help = "Enable debug mode")]
    debug: bool,

    #[arg(short, long, action = SetTrue, default_value_t = false, help = "Enable verbose mode")]
    verbose: bool,

    #[command(subcommand)]
    command: Option<cmds::Command>,
}

impl App {
    pub async fn run(&self) {
        // 初始化日志系统
        let mut layer = fmt::layer().with_target(true);
        let filter = if self.debug {
            layer = layer.with_file(true).with_line_number(true);
            EnvFilter::from_default_env().add_directive(Level::DEBUG.into())
        } else if self.verbose {
            layer = layer.with_file(true).with_line_number(true);
            EnvFilter::from_default_env().add_directive(Level::INFO.into())
        } else {
            EnvFilter::from_default_env().add_directive(Level::WARN.into())
        };
        tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .init();

        if let Some(cmd) = &self.command {
            match cmd {
                cmds::Command::Completion { shell } => {
                    let mut cmd = App::command();
                    generate(
                        shell.unwrap_or(Shell::Zsh),
                        &mut cmd,
                        env!("CARGO_PKG_NAME"),
                        &mut io::stdout(),
                    );
                }
                _ => {
                    if let Err(e) = cmd.invoke().await {
                        eprintln!("{e}");
                    }
                }
            }
        } else {
            let _ = App::command().print_help();
        }
    }
}
