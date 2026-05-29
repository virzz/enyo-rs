//! @alias: qr
//! @about: QR code generate and parse tools

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use image::{ImageBuffer, Luma, Rgb, RgbImage};
use qrcode::QrCode;

use enyo_core::{core::input, Action};

#[derive(Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    command: SubCmd,
}

#[derive(Subcommand)]
pub enum SubCmd {
    /// Binary string (0,1) to QR code image
    #[clap(alias = "bs")]
    Qrbs {
        /// Exchange 0/1
        #[arg(short = 'c', long)]
        exchange: bool,

        /// Output file path (use - for terminal)
        #[arg(short, long)]
        output: Option<String>,

        /// Input binary string data
        inputs: Option<Vec<String>>,
    },

    /// Parse QR code image
    #[clap(alias = "parse", alias = "p")]
    Qrparse {
        /// Also print QR image to terminal
        #[arg(short, long)]
        terminal: bool,

        /// Input file path or URL
        target: String,
    },

    /// Generate QR code image
    #[clap(alias = "gen", alias = "g")]
    Qrgen {
        /// Output file path (empty for terminal)
        #[arg(short, long)]
        output: Option<String>,

        /// Content to encode as QR code
        inputs: Option<Vec<String>>,
    },
}

/// 打印 QR 码到终端
fn print_qrcode_to_terminal(data: &[Vec<bool>]) -> String {
    let mut result = String::new();
    for row in data {
        for &col in row {
            if col {
                result.push_str("\x1b[48;5;0m  \x1b[0m"); // 黑色
            } else {
                result.push_str("\x1b[48;5;7m  \x1b[0m"); // 白色
            }
        }
        result.push('\n');
    }
    result
}

/// 从二进制字符串生成 QR 码图像
#[allow(clippy::needless_range_loop)]
fn zero_one_to_qrcode(s: &str, exchange: bool, output: Option<&str>) -> Result<String> {
    let flag = if exchange { '0' } else { '1' };
    let s: String = s.chars().filter(|c| *c == '0' || *c == '1').collect();
    let length = (s.len() as f64).sqrt() as usize;
    if length < 1 {
        return Err(anyhow!("Input data error"));
    }
    // 生成二维数组
    let mut data: Vec<Vec<bool>> = vec![vec![false; length]; length];
    let chars: Vec<char> = s.chars().collect();
    for y in 0..length {
        for x in 0..length {
            let idx = y * length + x;
            if idx < chars.len() {
                data[x][y] = chars[idx] == flag;
            }
        }
    }
    match output {
        Some("-") | None => {
            // 输出到终端
            Ok(print_qrcode_to_terminal(&data))
        }
        Some(path) => {
            // 保存为图像文件
            let scale = 10; // 放大倍数
            let img_size = length * scale;
            let mut img: RgbImage = ImageBuffer::new(img_size as u32, img_size as u32);
            for y in 0..length {
                for x in 0..length {
                    let color = if data[x][y] {
                        Rgb([0u8, 0u8, 0u8]) // 黑色
                    } else {
                        Rgb([255u8, 255u8, 255u8]) // 白色
                    };
                    // 放大像素
                    for dy in 0..scale {
                        for dx in 0..scale {
                            img.put_pixel((x * scale + dx) as u32, (y * scale + dy) as u32, color);
                        }
                    }
                }
            }
            img.save(path)?;
            Ok(format!("Generate [{path}] success"))
        }
    }
}

/// 生成 QR 码
fn generate_qrcode(content: &str, output: Option<&str>) -> Result<String> {
    let code = QrCode::new(content.as_bytes())?;
    match output {
        // 保存为图像文件
        Some(path) if !path.is_empty() && path != "-" => {
            let image = code.render::<Luma<u8>>().build();
            image.save(path)?;
            Ok(format!("Generate [{path}] success"))
        }
        // 使用简单字符输出到终端
        _ => Ok(code
            .render::<char>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .build()),
    }
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        match &self.command {
            SubCmd::Qrbs {
                exchange,
                output,
                inputs,
            } => {
                let data = input(inputs)?;
                let content = String::from_utf8_lossy(&data);
                let result = zero_one_to_qrcode(&content, *exchange, output.as_deref())?;
                println!("{result}");
            }
            SubCmd::Qrparse {
                terminal: _,
                target: _,
            } => {
                // QR 码解析需要更复杂的库支持，这里简化处理
                // 实际应用中可以使用 rqrr 或其他库
                return Err(anyhow!("QR code parsing is not yet implemented in Rust version. Please use external tools like zbarimg."));
            }
            SubCmd::Qrgen { output, inputs } => {
                let data = input(inputs)?;
                let content = String::from_utf8_lossy(&data).trim().to_string();
                let result = generate_qrcode(&content, output.as_deref())?;
                println!("{result}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one_to_qrcode() {
        let result = zero_one_to_qrcode(
            "100110101001000101001100110101001000101001100110101001000101001100110101001000101001",
            false,
            Some("-"),
        )
        .unwrap();
        println!("{result}");
    }

    #[test]
    fn test_generate_qrcode_terminal() {
        let result = generate_qrcode("Mozhu233", None).unwrap();
        println!("{result}");
    }

    #[tokio::test]
    async fn test_qrgen() {
        let cmd = Cmd {
            command: SubCmd::Qrgen {
                output: None,
                inputs: Some(vec!["Hello World".to_string()]),
            },
        };
        cmd.execute().await.unwrap();
    }
}
