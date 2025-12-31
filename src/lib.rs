use clap::{ArgAction::SetTrue, CommandFactory, Parser};
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub mod cmds;
pub mod core;

pub use core::CmdExecute;

#[derive(Parser)]
#[command(author, version= env!("CARGO_PKG_VERSION"), about, long_about = None)]
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
            if let Err(e) = cmd.invoke().await {
                eprintln!("{e}");
            }
        } else {
            let _ = App::command().print_help();
        }
    }
}
