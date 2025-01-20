use clap::Subcommand;

pub mod timestamp;
pub mod wechat;
// mod githack;
// mod basex;
// mod domain;

#[derive(Subcommand)]
pub enum Command {
    /// Print or parse timestamps
    #[clap(alias = "ts")]
    Timestamp(timestamp::Args),

    /// Decrypt Wechat DB
    #[clap(alias = "vx")]
    Wechat(wechat::Args),
}

impl Command {
    pub fn run(&self) {
        match self {
            Command::Timestamp(args) => timestamp::execute(args),
            Command::Wechat(args) => wechat::execute(args),
        }
    }
}
