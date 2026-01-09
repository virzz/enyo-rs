//! EXIF metadata operations

use anyhow::{anyhow, Context, Result};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
};

use super::{
    types::ImageFormatType,
    utils::{format_from_extension, load_image},
};

/// 读取 EXIF 信息
pub fn read_exif(target: &str, format: &str, show_all: bool) -> Result<String> {
    let file = File::open(target).with_context(|| format!("无法打开文件: {}", target))?;
    let mut bufreader = BufReader::new(file);

    let exif_reader = exif::Reader::new();
    let exif = exif_reader
        .read_from_container(&mut bufreader)
        .with_context(|| format!("无法读取 EXIF 数据: {}", target))?;

    let mut entries: Vec<(String, String, String)> = Vec::new();

    for field in exif.fields() {
        let tag_name = field.tag.to_string();
        let ifd_name = format!("{:?}", field.ifd_num);
        let value = field.display_value().with_unit(&exif).to_string();

        // 过滤未知标签（除非指定 --all）
        if !show_all && tag_name.starts_with("Tag(") {
            continue;
        }

        entries.push((ifd_name, tag_name, value));
    }

    if entries.is_empty() {
        return Ok("未找到 EXIF 数据".to_string());
    }

    match format {
        "json" => {
            let json_entries: Vec<serde_json::Value> = entries
                .iter()
                .map(|(ifd, tag, value)| {
                    serde_json::json!({
                        "ifd": ifd,
                        "tag": tag,
                        "value": value
                    })
                })
                .collect();
            Ok(serde_json::to_string_pretty(&json_entries)?)
        }
        _ => {
            // 表格格式
            use comfy_table::{presets::UTF8_FULL, Table};
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["IFD", "Tag", "Value"]);

            for (ifd, tag, value) in entries {
                // 截断过长的值
                let display_value = if value.len() > 60 {
                    format!("{}...", &value[..57])
                } else {
                    value
                };
                table.add_row(vec![ifd, tag, display_value]);
            }

            Ok(table.to_string())
        }
    }
}

/// 移除 EXIF 信息
pub fn strip_exif(input: &str, output: Option<&str>) -> Result<String> {
    let img = load_image(input)?;

    let output_path = match output {
        Some(path) => path.to_string(),
        None => input.to_string(),
    };

    // 根据输出格式保存（不包含 EXIF）
    let format = format_from_extension(&output_path).or_else(|| format_from_extension(input));

    match format {
        Some(ImageFormatType::Jpg) => {
            let rgb_img = img.to_rgb8();
            let mut output_file = BufWriter::new(
                File::create(&output_path)
                    .with_context(|| format!("无法创建输出文件: {}", output_path))?,
            );
            let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut output_file, 90);
            rgb_img.write_with_encoder(encoder)?;
        }
        Some(fmt) => {
            let image_format = fmt
                .to_image_format()
                .ok_or_else(|| anyhow!("不支持的格式"))?;
            img.save_with_format(&output_path, image_format)?;
        }
        None => {
            img.save(&output_path)?;
        }
    }

    Ok(format!("EXIF 已移除: {} -> {}", input, output_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use tempfile::TempDir;

    fn create_test_image(path: &str) -> Result<()> {
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(100, 100, |x, y| {
            Rgb([
                (x % 256) as u8,
                (y % 256) as u8,
                ((x + y) % 256) as u8,
            ])
        });
        img.save(path)?;
        Ok(())
    }

    #[test]
    fn test_read_exif_no_data() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");

        create_test_image(input_path.to_str().unwrap())?;

        let result = read_exif(input_path.to_str().unwrap(), "table", false);

        // PNG 文件通常没有 EXIF 数据
        assert!(result.is_err() || result.unwrap().contains("未找到 EXIF 数据"));
        Ok(())
    }

    #[test]
    fn test_read_exif_json_format() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");

        create_test_image(input_path.to_str().unwrap())?;

        let result = read_exif(input_path.to_str().unwrap(), "json", false);

        // 应该返回错误或空数据消息
        assert!(result.is_err() || result.unwrap().contains("未找到"));
        Ok(())
    }

    #[test]
    fn test_read_exif_nonexistent_file() {
        let result = read_exif("nonexistent.jpg", "table", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("无法打开文件"));
    }

    #[test]
    fn test_strip_exif() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.jpg");
        let output_path = temp_dir.path().join("output.jpg");

        create_test_image(input_path.to_str().unwrap())?;

        let result = strip_exif(
            input_path.to_str().unwrap(),
            Some(output_path.to_str().unwrap()),
        )?;

        assert!(result.contains("EXIF 已移除"));
        assert!(output_path.exists());
        Ok(())
    }

    #[test]
    fn test_strip_exif_in_place() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.jpg");

        create_test_image(input_path.to_str().unwrap())?;

        let result = strip_exif(input_path.to_str().unwrap(), None)?;

        assert!(result.contains("EXIF 已移除"));
        assert!(input_path.exists());
        Ok(())
    }

    #[test]
    fn test_strip_exif_nonexistent_file() {
        let result = strip_exif("nonexistent.jpg", Some("output.jpg"));
        assert!(result.is_err());
    }
}
