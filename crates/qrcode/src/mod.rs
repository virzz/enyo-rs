//! @alias: qr
//! @about: QR code generate and parse tools

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use image::{GrayImage, ImageBuffer, Luma, Rgb, RgbImage};
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

fn render_payload(payload: &[u8], terminal: bool) -> Result<String> {
    let text = String::from_utf8_lossy(payload).to_string();
    if !terminal {
        return Ok(text);
    }

    let code = QrCode::new(payload)?;
    let qrcode = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .build();
    Ok(format!("{qrcode}\n{text}"))
}

fn decode_qrcodes(img_gray: &GrayImage, terminal: bool) -> Result<(Vec<String>, Vec<String>)> {
    let mut decoder = quircs::Quirc::default();
    let codes = decoder.identify(
        img_gray.width() as usize,
        img_gray.height() as usize,
        img_gray.as_raw(),
    );

    let mut results = Vec::new();
    let mut errors = Vec::new();

    for code in codes {
        let code = match code {
            Ok(code) => code,
            Err(err) => {
                errors.push(format!("extract failed: {err}"));
                continue;
            }
        };

        match code.decode() {
            Ok(decoded) => results.push(render_payload(&decoded.payload, terminal)?),
            Err(err) => errors.push(format!("decode failed: {err}")),
        }
    }

    Ok((results, errors))
}

fn add_quiet_zone(img_gray: &GrayImage) -> GrayImage {
    let border = (img_gray.width().min(img_gray.height()) / 10).max(16);
    let mut padded = GrayImage::from_pixel(
        img_gray.width() + border * 2,
        img_gray.height() + border * 2,
        Luma([255]),
    );

    for (x, y, pixel) in img_gray.enumerate_pixels() {
        padded.put_pixel(x + border, y + border, *pixel);
    }

    padded
}

fn parse_qrcode_bytes(data: &[u8], terminal: bool) -> Result<String> {
    let img = image::load_from_memory(data).context("failed to load QR code image")?;
    let img_gray = img.into_luma8();
    let (mut results, mut errors) = decode_qrcodes(&img_gray, terminal)?;

    if results.is_empty() {
        let padded = add_quiet_zone(&img_gray);
        let (padded_results, padded_errors) = decode_qrcodes(&padded, terminal)?;
        results = padded_results;
        errors.extend(padded_errors);
    }

    if results.is_empty() {
        if errors.is_empty() {
            return Err(anyhow!("No QR code found"));
        }
        return Err(anyhow!("Failed to decode QR code: {}", errors.join("; ")));
    }

    Ok(results.join("\n"))
}

fn parse_qrcode(target: &str, terminal: bool) -> Result<String> {
    let data = std::fs::read(target).with_context(|| format!("failed to read [{target}]"))?;
    parse_qrcode_bytes(&data, terminal)
}

async fn parse_qrcode_target(target: &str, terminal: bool) -> Result<String> {
    if target.starts_with("http://") || target.starts_with("https://") {
        let data = reqwest::get(target)
            .await
            .with_context(|| format!("failed to request [{target}]"))?
            .error_for_status()
            .with_context(|| format!("failed to download [{target}]"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read response body from [{target}]"))?;
        return parse_qrcode_bytes(&data, terminal);
    }

    parse_qrcode(target, terminal)
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
            SubCmd::Qrparse { terminal, target } => {
                let result = parse_qrcode_target(target, *terminal).await?;
                println!("{result}");
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

    #[test]
    fn test_parse_generated_qrcode_image() {
        let temp_dir = tempfile::tempdir().unwrap();
        let image_path = temp_dir.path().join("qrcode.png");
        let image_path = image_path.to_string_lossy();

        generate_qrcode("Mozhu233", Some(&image_path)).unwrap();
        let result = parse_qrcode(&image_path, false).unwrap();

        assert_eq!(result, "Mozhu233");
    }

    #[test]
    fn test_parse_qrcode_without_quiet_zone() {
        let temp_dir = tempfile::tempdir().unwrap();
        let image_path = temp_dir.path().join("qrcode-no-quiet-zone.png");
        let image_path = image_path.to_string_lossy();
        let image = QrCode::new(b"Mozhu233")
            .unwrap()
            .render::<Luma<u8>>()
            .quiet_zone(false)
            .module_dimensions(10, 10)
            .build();

        image.save(&*image_path).unwrap();
        let result = parse_qrcode(&image_path, false).unwrap();

        assert_eq!(result, "Mozhu233");
    }
}
