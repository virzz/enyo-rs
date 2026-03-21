//! @alias: bx
//! @about: Base encoding/decoding tools (base16/32/36/58/62/64/91/100)

use anyhow::{Ok, Result};
use clap::{ArgAction::SetTrue, Parser, Subcommand};

mod base100;
mod base16;
mod base32;
mod base36;
mod base58;
mod base62;
mod base64;
mod base91;
mod ext;

use base100::Base100;
use base16::Base16;
use base32::Base32;
use base36::Base36;
use base58::Base58;
use base62::Base62;
use base64::{Base64Standard, Base64UrlSafe};
use base91::Base91;
use ext::fuzzing;

use crate::{core, Action};

pub trait BaseX {
    fn encode(data: &[u8]) -> Result<String>;
    fn decode(data: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Parser)]
#[command(name = "basex")]
pub struct Cmd {
    /// Output in binary format
    #[arg(short, long = "bin", default_value_t = false, action = SetTrue)]
    output_bin: bool,

    /// Base encoding sub command
    #[command(subcommand)]
    cmds: Option<SubCommand>,

    /// Base encoding input (string path, or stdin if not provided)
    #[arg(global = true, trailing_var_arg = true)]
    input: Option<Vec<String>>,
}

#[derive(Subcommand)]
pub enum SubCommand {
    /// Base16 (hex) encoding
    #[command(alias = "b16e")]
    Base16e,

    /// Base16 (hex) decoding
    #[command(alias = "b16d")]
    Base16d,

    /// Base32 encoding
    #[command(alias = "b32e")]
    Base32e,

    /// Base32 decoding
    #[command(alias = "b32d")]
    Base32d,

    /// Base36 encoding
    #[command(alias = "b36e")]
    Base36e,

    /// Base36 decoding
    #[command(alias = "b36d")]
    Base36d,

    /// Base58 encoding
    #[command(alias = "b58e")]
    Base58e,

    /// Base58 decoding
    #[command(alias = "b58d")]
    Base58d,

    /// Base62 encoding
    #[command(alias = "b62e")]
    Base62e,

    /// Base62 decoding
    #[command(alias = "b62d")]
    Base62d,

    /// Base64 encoding
    #[command(alias = "b64e")]
    Base64e {
        /// Use URL-safe alphabet (替换 + 为 -, / 为 _)
        #[arg(short = 'u', long = "url", action = SetTrue, default_value_t = false)]
        url_safe: bool,
    },

    /// Base64 decoding
    #[command(alias = "b64d")]
    Base64d {
        /// Use URL-safe alphabet (替换 + 为 -, / 为 _)
        #[arg(short = 'u', long = "url", action = SetTrue, default_value_t = false)]
        url_safe: bool,
    },

    /// Base91 encoding
    #[command(alias = "b91e")]
    Base91e,

    /// Base91 decoding
    #[command(alias = "b91d")]
    Base91d,

    /// Base100 (emoji) encoding
    #[command(alias = "b100e")]
    Base100e,

    /// Base100 (emoji) decoding
    #[command(alias = "b100d")]
    Base100d,
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        let data = core::input(&self.input.clone())?;
        match &self.cmds {
            Some(cmd) => match cmd {
                SubCommand::Base16e => {
                    println!("{}", Base16::encode(&data)?);
                }
                SubCommand::Base16d => {
                    core::output(&Base16::decode(&data)?, self.output_bin)?;
                }
                SubCommand::Base32e => {
                    println!("{}", Base32::encode(&data)?);
                }
                SubCommand::Base32d => {
                    core::output(&Base32::decode(&data)?, self.output_bin)?;
                }
                SubCommand::Base36e => {
                    println!("{}", Base36::encode(&data)?);
                }
                SubCommand::Base36d => {
                    core::output(&Base36::decode(&data)?, self.output_bin)?;
                }
                SubCommand::Base58e => {
                    println!("{}", Base58::encode(&data)?);
                }
                SubCommand::Base58d => {
                    core::output(&Base58::decode(&data)?, self.output_bin)?;
                }
                SubCommand::Base62e => {
                    println!("{}", Base62::encode(&data)?);
                }
                SubCommand::Base62d => {
                    core::output(&Base62::decode(&data)?, self.output_bin)?;
                }
                SubCommand::Base64e { url_safe } => {
                    if *url_safe {
                        println!("{}", Base64UrlSafe::encode(&data)?);
                    } else {
                        println!("{}", Base64Standard::encode(&data)?);
                    }
                }
                SubCommand::Base64d { url_safe } => {
                    let result = if *url_safe {
                        Base64UrlSafe::decode(&data)?
                    } else {
                        Base64Standard::decode(&data)?
                    };
                    core::output(&result, self.output_bin)?;
                }
                SubCommand::Base91e => {
                    println!("{}", Base91::encode(&data)?);
                }
                SubCommand::Base91d => {
                    core::output(&Base91::decode(&data)?, self.output_bin)?;
                }
                SubCommand::Base100e => {
                    println!("{}", Base100::encode(&data)?);
                }
                SubCommand::Base100d => {
                    core::output(&Base100::decode(&data)?, self.output_bin)?;
                }
            },
            None => {
                let result = fuzzing(&data).await?;
                for r in result {
                    println!("{}", r.verbose());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_base64_encode() {
        let cmd = Cmd {
            input: Some(vec!["test".to_string()]),
            output_bin: false,
            cmds: Some(SubCommand::Base64e { url_safe: false }),
        };
        cmd.execute().await.unwrap();
        // 应该输出 "dGVzdA=="
    }

    #[tokio::test]
    async fn test_base64_decode() {
        let cmd = Cmd {
            input: Some(vec!["dGVzdA==".to_string()]),
            output_bin: false,
            cmds: Some(SubCommand::Base64d { url_safe: false }),
        };
        cmd.execute().await.unwrap();
        // 应该输出 "test"
    }

    #[tokio::test]
    async fn test_execute() {
        let cmd = Cmd {
            input: Some(vec!["test".to_string()]),
            output_bin: false,
            cmds: None,
        };
        cmd.execute().await.unwrap();
    }
}
