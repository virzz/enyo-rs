use anyhow::Result;
use clap::Subcommand;

pub mod timestamp;
pub mod wechat;
pub mod sitemap;
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

    /// Generate sitemap with given URLs
    #[clap(alias = "sm")]
    Sitemap(sitemap::Args),
}

impl Command {
    pub fn run(&self)->Result<()> {
        match self {
            Command::Timestamp(args) => timestamp::execute(args),
            Command::Wechat(args) => wechat::execute(args),
            Command::Sitemap(args) => sitemap::execute(args),
        }
    }
}
