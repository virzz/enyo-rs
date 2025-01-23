use clap::{arg, command, Parser};

pub mod modules;
pub use modules::*;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

fn main() {
    let cli = Args::parse();
    if let Some(cmd) = cli.command {
        match cmd.run() {
            Ok(_) => {}
            Err(e) => eprintln!("{}", e),
        };
    }
}
