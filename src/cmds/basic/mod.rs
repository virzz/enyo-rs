//! @about: Basic utils tools (URL, String, Bin, XOR, Random)

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

mod bin;
mod string;
mod url;
mod xor;

use crate::{
    core::{input, output},
    CmdExecute,
};

#[derive(Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    command: Option<SubCmd>,

    /// Any input data (string, file path, or stdin if not provided)
    #[arg(global = true, trailing_var_arg = true)]
    inputs: Option<Vec<String>>,
}

#[derive(Subcommand)]
pub enum SubCmd {
    // === URL 编码 ===
    /// URL encode
    #[clap(alias = "urle", alias = "urlencode")]
    UrlEncode {
        /// Raw encode: + -> %20
        #[arg(short, long)]
        raw: bool,
    },

    /// URL decode
    #[clap(alias = "urld", alias = "urldecode")]
    UrlDecode,

    // === Bin 编码 ===
    /// Bin -> Hex (将二进制数据转为十六进制)
    #[clap(alias = "b2h")]
    Bin2Hex,

    /// Hex -> Bin (将十六进制转为二进制数据)
    #[clap(alias = "h2b")]
    Hex2Bin,

    // === String 相关 ===
    /// String -> ASCII (字符串转ASCII码)
    #[clap(alias = "chr2ord", alias = "ords")]
    Str2Ascii,

    /// ASCII -> String (ASCII码转字符串)
    #[clap(alias = "ord2str", alias = "chrs")]
    Ascii2Str,

    /// Hex -> String (十六进制转字符串)
    #[clap(alias = "h2s")]
    Hex2Str,

    /// String -> Hex (字符串转十六进制)
    #[clap(alias = "s2h")]
    Str2Hex,

    /// Hex -> Dec (十六进制转十进制)
    #[clap(alias = "h2d")]
    Hex2Dec,

    /// Dec -> Hex (十进制转十六进制)
    #[clap(alias = "d2h")]
    Dec2Hex,

    /// Hex -> Bytes String (十六进制转字节字符串 b'...')
    #[clap(alias = "h2bs")]
    Hex2Bytes,

    /// Bytes String -> Hex (字节字符串转十六进制)
    #[clap(alias = "bs2h")]
    Bytes2Hex,

    /// Bytes String -> String (字节字符串转字符串)
    #[clap(alias = "bs2s")]
    Bytes2Str,

    // === XOR 加密 ===
    /// XOR two strings
    Xor,

    // === 随机字符串 ===
    /// Generate random string
    #[clap(alias = "rstr")]
    RandStr {
        /// Length of random string (default: 8)
        #[arg(default_value = "8")]
        length: usize,

        /// Regex for allowed chars (default: a-z0-9)
        #[arg(short, long, default_value = "a-z0-9")]
        regex: String,

        /// Use uppercase letters only
        #[arg(short, long)]
        upper: bool,

        /// Use lowercase letters only
        #[arg(short, long)]
        lower: bool,

        /// Use digits only
        #[arg(short, long)]
        digit: bool,

        /// Use hex characters only (0-9a-f)
        #[arg(short = 'x', long)]
        hex: bool,
    },
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        if let Some(command) = &self.command {
            // RandStr 命令不需要输入数据
            let (data, data_str) = match command {
                SubCmd::RandStr { .. } => (Vec::new(), String::new()),
                _ => {
                    let d = input(&self.inputs)?;
                    let s = String::from_utf8_lossy(&d).trim().to_string();
                    (d, s)
                }
            };

            match command {
                // URL
                SubCmd::UrlEncode { raw } => {
                    let result = url::url_encode(&data_str, *raw)?;
                    println!("{result}");
                }
                SubCmd::UrlDecode => {
                    let result = url::url_decode(&data_str)?;
                    println!("{result}");
                }

                // Bin
                SubCmd::Bin2Hex => {
                    let result = bin::bin_to_hex(&data)?;
                    println!("{result}");
                }
                SubCmd::Hex2Bin => {
                    output(&bin::hex_to_bin(&data_str)?, false)?;
                }

                // String
                SubCmd::Str2Ascii => {
                    let result = string::string_to_ascii(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Ascii2Str => {
                    let result = string::ascii_to_string(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Hex2Str => {
                    let result = string::hex_to_string(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Str2Hex => {
                    let result = string::string_to_hex(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Hex2Dec => {
                    let result = string::hex_to_dec(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Dec2Hex => {
                    let result = string::dec_to_hex(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Hex2Bytes => {
                    let result = string::hex_to_byte_string(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Bytes2Hex => {
                    let result = string::byte_string_to_hex(&data_str)?;
                    println!("{result}");
                }
                SubCmd::Bytes2Str => {
                    let result = string::byte_string_to_string(&data_str)?;
                    println!("{result}");
                }

                // XOR
                SubCmd::Xor => {
                    if let Some(inputs) = &self.inputs {
                        if inputs.len() >= 2 {
                            let result = xor::xor(&inputs[0], &inputs[1])?;
                            println!("{result}");
                        } else {
                            return Err(anyhow!("XOR requires at least 2 arguments"));
                        }
                    } else {
                        return Err(anyhow!("XOR requires at least 2 arguments"));
                    }
                }

                // Random String
                SubCmd::RandStr {
                    length,
                    regex,
                    upper,
                    lower,
                    digit,
                    hex,
                } => {
                    let charset = if *upper {
                        "A-Z"
                    } else if *lower {
                        "a-z"
                    } else if *digit {
                        "0-9"
                    } else if *hex {
                        "0-9a-f"
                    } else {
                        regex.as_str()
                    };
                    let result = string::random_string(*length, charset)?;
                    println!("{result}");
                }
            }
            return Ok(());
        }
        Err(anyhow!("No command provided"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_url_encode() {
        let cmd = Cmd {
            command: Some(SubCmd::UrlEncode { raw: false }),
            inputs: Some(vec!["hello world".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_url_decode() {
        let cmd = Cmd {
            command: Some(SubCmd::UrlDecode),
            inputs: Some(vec!["hello%20world".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_bin2hex() {
        let cmd = Cmd {
            command: Some(SubCmd::Bin2Hex),
            inputs: Some(vec!["test".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_str2ascii() {
        let cmd = Cmd {
            command: Some(SubCmd::Str2Ascii),
            inputs: Some(vec!["test_string_virzz".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_xor() {
        let cmd = Cmd {
            command: Some(SubCmd::Xor),
            inputs: Some(vec!["aaaa".to_string(), "1111".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_randstr() {
        let cmd = Cmd {
            command: Some(SubCmd::RandStr {
                length: 16,
                regex: "a-z0-9".to_string(),
                upper: false,
                lower: false,
                digit: false,
                hex: false,
            }),
            inputs: None,
        };
        cmd.execute().await.unwrap();
    }
}
