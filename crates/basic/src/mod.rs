//! @about: Basic utils tools (URL, String, Bin, XOR, Random)

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

mod bin;
mod ip;
mod string;
mod url;
mod xor;

use enyo_core::{
    core::{input, inputs, Input, InputSource},
    Action,
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
    /// URL encode
    #[clap(alias = "urle")]
    Urlencode {
        /// Raw encode: + -> %20
        #[arg(short, long)]
        raw: bool,
    },

    /// URL decode
    #[clap(alias = "urld")]
    Urldecode,

    /// Bin -> Hex (将二进制数据转为十六进制)
    #[clap(alias = "b2h")]
    Bin2hex,

    /// Hex -> Bin (将十六进制转为二进制数据)
    #[clap(alias = "h2b")]
    Hex2bin,

    /// String -> ASCII (字符串转ASCII码)
    #[clap(alias = "chr2ord", alias = "ords")]
    Str2ascii,

    /// ASCII -> String (ASCII码转字符串)
    #[clap(alias = "ord2str", alias = "chrs")]
    Ascii2str,

    /// Hex -> String (十六进制转字符串)
    #[clap(alias = "h2s")]
    Hex2str,

    /// String -> Hex (字符串转十六进制)
    #[clap(alias = "s2h")]
    Str2hex,

    /// Hex -> Dec (十六进制转十进制)
    #[clap(alias = "h2d")]
    Hex2dec,

    /// Dec -> Hex (十进制转十六进制)
    #[clap(alias = "d2h")]
    Dec2hex,

    /// Hex -> Bytes String (十六进制转字节字符串 b'...')
    #[clap(alias = "h2bs")]
    Hex2bytes,

    /// Bytes String -> Hex (字节字符串转十六进制)
    #[clap(alias = "bs2h")]
    Bytes2hex,

    /// Bytes String -> String (字节字符串转字符串)
    #[clap(alias = "bs2s")]
    Bytes2str,

    /// IP conversion report: ip2hex, ip2dec, ip2oct and reverse
    #[clap(alias = "ips")]
    Ip {
        /// Print JSON output
        #[arg(long)]
        json: bool,
    },

    /// IPv4 conversion report: IPv4 -> {hex, dec, oct}
    Ip2all {
        /// Print JSON output
        #[arg(long)]
        json: bool,
    },

    /// Any IP format -> IPv4, skip invalid values
    Any2ip {
        /// Print JSON output
        #[arg(long)]
        json: bool,
    },

    /// IPv4 -> Hex
    Ip2hex,

    /// Hex -> IPv4
    Hex2ip,

    /// IPv4 -> Dec
    Ip2dec,

    /// Dec -> IPv4
    Dec2ip,

    /// IPv4 -> Oct
    Ip2oct,

    /// Oct -> IPv4
    Oct2ip,

    /// XOR two strings
    Xor,

    /// Generate random string
    #[clap(alias = "rstr")]
    Randstr {
        /// Length of random string (default: 8)
        #[arg(long = "len", default_value = "8")]
        length: usize,

        /// Regex for allowed chars (default: a-z0-9)
        #[arg(short = 'r', long, default_value = "a-z0-9")]
        regex: String,

        /// Use uppercase letters only
        #[arg(short = 'u', long, default_value_t = false)]
        upper: bool,

        /// Use lowercase letters only
        #[arg(short = 'l', long, default_value_t = false)]
        lower: bool,

        /// Use digits only
        #[arg(short = 'd', long, default_value_t = false)]
        digit: bool,

        /// Use hex characters only (0-9a-f)
        #[arg(short = 'x', long, default_value_t = false)]
        hex: bool,
    },
}
#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        if let Some(command) = &self.command {
            if matches!(
                command,
                SubCmd::Ip { .. } | SubCmd::Ip2all { .. } | SubCmd::Any2ip { .. }
            ) {
                let values = input_values(self.inputs.clone())?;
                match command {
                    SubCmd::Ip { json } => {
                        if *json {
                            println!("{}", ip::format_ip_values_json(&values)?);
                        } else {
                            println!("{}", ip::format_ip_values(&values)?);
                        }
                    }
                    SubCmd::Ip2all { json } => {
                        if *json {
                            println!("{}", ip::format_ipv4_values_json(&values)?);
                        } else {
                            println!("{}", ip::format_ipv4_values(&values)?);
                        }
                    }
                    SubCmd::Any2ip { json } => {
                        if *json {
                            println!("{}", ip::format_any_ips_json(&values)?);
                        } else {
                            println!("{}", ip::format_any_ips(&values)?);
                        }
                    }
                    _ => unreachable!("IP multi-value commands are handled above"),
                }
                return Ok(());
            }

            let (data, data_str) = match command {
                // Randstr 命令不需要输入数据
                SubCmd::Randstr { .. } => (
                    Input {
                        data: Vec::new(),
                        source: InputSource::Arg,
                    },
                    String::new(),
                ),
                _ => {
                    let d = input(&self.inputs)?;
                    let s = String::from_utf8_lossy(&d).trim().to_string();
                    (d, s)
                }
            };

            match command {
                // URL
                SubCmd::Urlencode { raw } => {
                    println!("{}", url::url_encode(&data_str, *raw)?);
                }
                SubCmd::Urldecode => {
                    println!("{}", url::url_decode(&data_str)?);
                }
                // Bin
                SubCmd::Bin2hex => {
                    println!("{}", bin::bin_to_hex(&data)?);
                }
                SubCmd::Hex2bin => {
                    println!("{}", String::from_utf8_lossy(&bin::hex_to_bin(&data_str)?));
                }

                // String
                SubCmd::Str2ascii => {
                    println!("{}", string::string_to_ascii(&data_str)?);
                }
                SubCmd::Ascii2str => {
                    println!("{}", string::ascii_to_string(&data_str)?);
                }
                SubCmd::Hex2str => {
                    println!("{}", string::hex_to_string(&data_str)?);
                }
                SubCmd::Str2hex => {
                    println!("{}", string::string_to_hex(&data_str)?);
                }
                SubCmd::Hex2dec => {
                    println!("{}", string::hex_to_dec(&data_str)?);
                }
                SubCmd::Dec2hex => {
                    println!("{}", string::dec_to_hex(&data_str)?);
                }
                SubCmd::Hex2bytes => {
                    println!("{}", string::hex_to_byte_string(&data_str)?);
                }
                SubCmd::Bytes2hex => {
                    println!("{}", string::byte_string_to_hex(&data_str)?);
                }
                SubCmd::Bytes2str => {
                    println!("{}", string::byte_string_to_string(&data_str)?);
                }
                SubCmd::Ip { .. } | SubCmd::Ip2all { .. } | SubCmd::Any2ip { .. } => {
                    unreachable!("IP multi-value commands are handled before common input parsing")
                }
                SubCmd::Ip2hex => {
                    println!("{}", ip::ip_to_hex(&data_str)?);
                }
                SubCmd::Hex2ip => {
                    println!("{}", ip::hex_to_ip(&data_str)?);
                }
                SubCmd::Ip2dec => {
                    println!("{}", ip::ip_to_dec(&data_str)?);
                }
                SubCmd::Dec2ip => {
                    println!("{}", ip::dec_to_ip(&data_str)?);
                }
                SubCmd::Ip2oct => {
                    println!("{}", ip::ip_to_oct(&data_str)?);
                }
                SubCmd::Oct2ip => {
                    println!("{}", ip::oct_to_ip(&data_str)?);
                }

                // XOR
                SubCmd::Xor => {
                    if let Some(inputs) = &self.inputs {
                        if inputs.len() >= 2 {
                            println!("{}", xor::xor(&inputs[0], &inputs[1])?);
                            return Ok(());
                        }
                    }
                    return Err(anyhow!("XOR requires at least 2 arguments"));
                }

                // Random String
                SubCmd::Randstr {
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
                    println!("{}", string::random_string(*length, charset)?);
                }
            }
            return Ok(());
        }
        Err(anyhow!("No command provided"))
    }
}

fn input_values(args: Option<Vec<String>>) -> Result<Vec<String>> {
    Ok(inputs(args)?
        .into_iter()
        .flat_map(|input| {
            input
                .to_string_lossy()
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_report_from_ip() {
        let result = ip::format_ip_values_json(&["127.0.0.1".to_string()]).unwrap();
        assert_eq!(
            result,
            r#"[{"ip":"127.0.0.1","hex":"0x7f000001","dec":"2130706433","oct":"0177.000.000.001"}]"#
        );
    }

    #[test]
    fn test_ip_report_defaults_to_text() {
        let result = ip::format_ip_values(&["127.0.0.1".to_string()]).unwrap();
        assert_eq!(
            result,
            "IP: 127.0.0.1\nHex: 0x7f000001\nDec: 2130706433\nOct: 0177.000.000.001\n"
        );
    }

    #[test]
    fn test_ip_report_from_encoded_values() {
        let values = vec![
            "0x7f000001".to_string(),
            "2130706433".to_string(),
            "0177.000.000.001".to_string(),
        ];
        let result = ip::format_ip_values_json(&values).unwrap();
        assert_eq!(result.matches(r#""ip":"127.0.0.1""#).count(), 3);
    }

    #[test]
    fn test_ip2all_requires_ipv4_values() {
        let values = vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()];
        let result = ip::format_ipv4_values(&values).unwrap();
        assert!(result.contains("IP: 127.0.0.1\nHex: 0x7f000001\nDec: 2130706433"));
        assert!(result.contains("IP: 10.0.0.1\nHex: 0x0a000001\nDec: 167772161"));

        let result = ip::format_ipv4_values_json(&values).unwrap();
        assert!(result.contains(r#""ip":"127.0.0.1""#));
        assert!(result.contains(r#""ip":"10.0.0.1""#));
    }

    #[test]
    fn test_any2ip_skips_invalid_values() {
        let values = vec![
            "bad".to_string(),
            "0x7f000001".to_string(),
            "999999999999".to_string(),
            "0177.000.000.001".to_string(),
        ];
        let result = ip::format_any_ips_json(&values).unwrap();
        assert_eq!(result, r#"["127.0.0.1","127.0.0.1"]"#);

        let result = ip::format_any_ips(&values).unwrap();
        assert_eq!(result, "127.0.0.1\n127.0.0.1");
    }

    #[test]
    fn test_ip_direct_conversions() {
        assert_eq!(ip::ip_to_hex("127.0.0.1").unwrap(), "0x7f000001");
        assert_eq!(ip::hex_to_ip("0x7f000001").unwrap(), "127.0.0.1");
        assert_eq!(ip::ip_to_dec("127.0.0.1").unwrap(), "2130706433");
        assert_eq!(ip::dec_to_ip("2130706433").unwrap(), "127.0.0.1");
        assert_eq!(ip::ip_to_oct("127.0.0.1").unwrap(), "0177.000.000.001");
        assert_eq!(ip::oct_to_ip("0177.000.000.001").unwrap(), "127.0.0.1");
    }

    #[test]
    fn test_any_ip_prefers_octal_for_dotted_leading_zero_values() {
        let values = vec!["00000100.00000011.00000010.00000001".to_string()];
        let result = ip::format_any_ips(&values).unwrap();
        assert_eq!(result, "64.9.8.1");
    }

    #[test]
    fn test_any2ip_skips_binary_values() {
        let values = vec!["01111111.00000000.00000000.00000001".to_string()];
        let result = ip::format_any_ips(&values).unwrap();
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn test_url_encode() {
        let cmd = Cmd {
            command: Some(SubCmd::Urlencode { raw: false }),
            inputs: Some(vec!["hello world".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_url_decode() {
        let cmd = Cmd {
            command: Some(SubCmd::Urldecode),
            inputs: Some(vec!["hello%20world".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_bin2hex() {
        let cmd = Cmd {
            command: Some(SubCmd::Bin2hex),
            inputs: Some(vec!["test".to_string()]),
        };
        cmd.execute().await.unwrap();
    }

    #[tokio::test]
    async fn test_str2ascii() {
        let cmd = Cmd {
            command: Some(SubCmd::Str2ascii),
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
            command: Some(SubCmd::Randstr {
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
