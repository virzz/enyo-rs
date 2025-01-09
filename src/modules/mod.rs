// mod time;
// pub use time::TimeCmd;

// mod domain;
// pub use domain::*;

// mod basex;
// pub use basex::*;

// mod githack;
// pub use githack::GithackCmd;

use clap::Subcommand;

pub mod timestamp;

#[derive(Subcommand)]
pub enum Command {
    /// Print or parse timestamps
    #[clap(alias = "ts")]
    Timestamp(timestamp::Args),
}

impl Command {
    pub fn run(&self) {
        match self {
            Command::Timestamp(args) => timestamp::execute(args),
        }
    }
}
