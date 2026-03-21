//! @about: Hash functions (MD2/4/5, SHA1/2/3, RIPEMD160, bcrypt, MySQL, NTLM)

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

mod bcrypt_hash;
mod hasher;
mod hmac_hash;
mod mysql;
mod ntlm;

use crate::{core::input, Action};

#[derive(Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    command: SubCmd,

    /// Input data (string, file path, or stdin if not provided)
    #[arg(global = true, trailing_var_arg = true)]
    inputs: Option<Vec<String>>,
}

#[derive(Clone, ValueEnum)]
pub enum Sha2Type {
    #[value(name = "224")]
    Sha224,
    #[value(name = "256")]
    Sha256,
    #[value(name = "384")]
    Sha384,
    #[value(name = "512")]
    Sha512,
    #[value(name = "512224")]
    Sha512_224,
    #[value(name = "512256")]
    Sha512_256,
}

#[derive(Clone, ValueEnum)]
pub enum Sha3Type {
    #[value(name = "224")]
    Sha3_224,
    #[value(name = "256")]
    Sha3_256,
    #[value(name = "384")]
    Sha3_384,
    #[value(name = "512")]
    Sha3_512,
}

#[derive(Subcommand)]
pub enum SubCmd {
    /// MD2 hash algorithm
    Md2 {
        /// HMAC key
        #[arg(short = 's', long)]
        hmac: Option<String>,
        /// Output raw bytes
        #[arg(short, long)]
        raw: bool,
    },

    /// MD4 hash algorithm
    Md4 {
        /// HMAC key
        #[arg(short = 's', long)]
        hmac: Option<String>,
        /// Output raw bytes
        #[arg(short, long)]
        raw: bool,
    },

    /// MD5 hash algorithm
    Md5 {
        /// HMAC key
        #[arg(short = 's', long)]
        hmac: Option<String>,
        /// Output raw bytes
        #[arg(short, long)]
        raw: bool,
    },

    /// SHA1 hash algorithm
    Sha1 {
        /// HMAC key
        #[arg(short = 's', long)]
        hmac: Option<String>,
        /// Output raw bytes
        #[arg(short, long)]
        raw: bool,
    },

    /// SHA2 hash algorithm (224|256|384|512|512224|512256)
    Sha2 {
        /// Hash type
        #[arg(short = 't', long, default_value = "256")]
        r#type: Sha2Type,
        /// HMAC key
        #[arg(short = 's', long)]
        hmac: Option<String>,
        /// Output raw bytes
        #[arg(short, long)]
        raw: bool,
    },

    /// SHA3 hash algorithm (224|256|384|512)
    Sha3 {
        /// Hash type
        #[arg(short = 't', long, default_value = "256")]
        r#type: Sha3Type,
        /// HMAC key
        #[arg(short = 's', long)]
        hmac: Option<String>,
        /// Output raw bytes
        #[arg(short, long)]
        raw: bool,
    },

    /// RIPEMD160 hash algorithm
    #[clap(alias = "ripemd160")]
    Ripemd {
        /// HMAC key
        #[arg(short = 's', long)]
        hmac: Option<String>,
        /// Output raw bytes
        #[arg(short, long)]
        raw: bool,
    },

    /// Bcrypt hash (generate or compare)
    Bcrypt {
        #[command(subcommand)]
        action: BcryptAction,
    },

    /// MySQL Hash password (pre-4.1)
    Mysql,

    /// MySQL5 Hash password (4.1+ SHA1)
    Mysql5,

    /// NTLM Hash password (MD4 of UTF-16LE)
    Ntlm,
}

#[derive(Subcommand)]
pub enum BcryptAction {
    /// Generate bcrypt hash
    #[clap(alias = "gen", alias = "g")]
    Generate {
        /// bcrypt cost (4-31, default: 12)
        #[arg(short, long, default_value = "12")]
        cost: u32,
    },

    /// Compare bcrypt hash
    #[clap(alias = "comp", alias = "c")]
    Compare {
        /// Hashed value
        hashed: String,
        /// Password to compare
        password: String,
    },
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        let data = input(&self.inputs)?;

        match &self.command {
            SubCmd::Md2 { hmac, raw } => {
                let result = if let Some(key) = hmac {
                    hmac_hash::hmac_md5(&data, key.as_bytes())? // MD2 HMAC not commonly supported
                } else {
                    hasher::md2_hash(&data)?
                };
                output_hash(&result, *raw);
            }
            SubCmd::Md4 { hmac, raw } => {
                let result = if let Some(key) = hmac {
                    hmac_hash::hmac_md4(&data, key.as_bytes())?
                } else {
                    hasher::md4_hash(&data)?
                };
                output_hash(&result, *raw);
            }
            SubCmd::Md5 { hmac, raw } => {
                let result = if let Some(key) = hmac {
                    hmac_hash::hmac_md5(&data, key.as_bytes())?
                } else {
                    hasher::md5_hash(&data)?
                };
                output_hash(&result, *raw);
            }
            SubCmd::Sha1 { hmac, raw } => {
                let result = if let Some(key) = hmac {
                    hmac_hash::hmac_sha1(&data, key.as_bytes())?
                } else {
                    hasher::sha1_hash(&data)?
                };
                output_hash(&result, *raw);
            }
            SubCmd::Sha2 { r#type, hmac, raw } => {
                let result = if let Some(key) = hmac {
                    hmac_hash::hmac_sha2(&data, key.as_bytes(), r#type)?
                } else {
                    hasher::sha2_hash(&data, r#type)?
                };
                output_hash(&result, *raw);
            }
            SubCmd::Sha3 { r#type, hmac, raw } => {
                let result = if let Some(key) = hmac {
                    hmac_hash::hmac_sha3(&data, key.as_bytes(), r#type)?
                } else {
                    hasher::sha3_hash(&data, r#type)?
                };
                output_hash(&result, *raw);
            }
            SubCmd::Ripemd { hmac, raw } => {
                let result = if let Some(key) = hmac {
                    hmac_hash::hmac_ripemd160(&data, key.as_bytes())?
                } else {
                    hasher::ripemd160_hash(&data)?
                };
                output_hash(&result, *raw);
            }
            SubCmd::Bcrypt { action } => match action {
                BcryptAction::Generate { cost } => {
                    let password = String::from_utf8_lossy(&data);
                    let result = bcrypt_hash::bcrypt_generate(&password, *cost)?;
                    println!("{result}");
                }
                BcryptAction::Compare { hashed, password } => {
                    bcrypt_hash::bcrypt_compare(hashed, password)?;
                    println!("Compare OK");
                }
            },
            SubCmd::Mysql => {
                let result = mysql::mysql_hash(&data);
                println!("{result}");
            }
            SubCmd::Mysql5 => {
                let result = mysql::mysql5_hash(&data);
                println!("{result}");
            }
            SubCmd::Ntlm => {
                let result = ntlm::ntlm_hash(&data);
                println!("{result}");
            }
        }
        Ok(())
    }
}

fn output_hash(hash: &[u8], raw: bool) {
    if raw {
        print!("{}", String::from_utf8_lossy(hash));
    } else {
        println!("{}", hex::encode(hash));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_TEXT: &str =
        "Let life be beautiful like summer flowers And Death like autumn leaves.";

    #[tokio::test]
    async fn test_md5() {
        let cmd = Cmd {
            command: SubCmd::Md5 {
                hmac: None,
                raw: false,
            },
            inputs: Some(vec![PLAIN_TEXT.to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_sha1() {
        let cmd = Cmd {
            command: SubCmd::Sha1 {
                hmac: None,
                raw: false,
            },
            inputs: Some(vec![PLAIN_TEXT.to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_sha256() {
        let cmd = Cmd {
            command: SubCmd::Sha2 {
                r#type: Sha2Type::Sha256,
                hmac: None,
                raw: false,
            },
            inputs: Some(vec![PLAIN_TEXT.to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_sha256_hmac() {
        let cmd = Cmd {
            command: SubCmd::Sha2 {
                r#type: Sha2Type::Sha256,
                hmac: Some("virzz".to_string()),
                raw: false,
            },
            inputs: Some(vec![PLAIN_TEXT.to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_mysql() {
        let cmd = Cmd {
            command: SubCmd::Mysql,
            inputs: Some(vec!["test".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_mysql5() {
        let cmd = Cmd {
            command: SubCmd::Mysql5,
            inputs: Some(vec!["test".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_ntlm() {
        let cmd = Cmd {
            command: SubCmd::Ntlm,
            inputs: Some(vec!["testasdvafsd".to_string()]),
        };
        cmd.execute().await.unwrap();
    }
}
