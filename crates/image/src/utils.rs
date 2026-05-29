//! Image utility functions

use anyhow::{Context, Result};
use image::{DynamicImage, ImageReader};
use std::path::Path;

use super::types::ImageFormatType;

/// 加载图片
pub fn load_image(path: &str) -> Result<DynamicImage> {
    let img = ImageReader::open(path)
        .with_context(|| format!("无法打开图片文件: {}", path))?
        .decode()
        .with_context(|| format!("无法解码图片: {}", path))?;
    Ok(img)
}

/// 根据文件扩展名推断格式
pub fn format_from_extension(path: &str) -> Option<ImageFormatType> {
    let ext = Path::new(path).extension()?.to_str()?.to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => Some(ImageFormatType::Jpg),
        "png" => Some(ImageFormatType::Png),
        "webp" => Some(ImageFormatType::Webp),
        "ico" => Some(ImageFormatType::Ico),
        "bmp" => Some(ImageFormatType::Bmp),
        "gif" => Some(ImageFormatType::Gif),
        "tiff" | "tif" => Some(ImageFormatType::Tiff),
        _ => None,
    }
}

/// 格式化文件大小
pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_from_extension() {
        assert_eq!(
            format_from_extension("test.jpg"),
            Some(ImageFormatType::Jpg)
        );
        assert_eq!(
            format_from_extension("test.jpeg"),
            Some(ImageFormatType::Jpg)
        );
        assert_eq!(
            format_from_extension("test.png"),
            Some(ImageFormatType::Png)
        );
        assert_eq!(
            format_from_extension("test.webp"),
            Some(ImageFormatType::Webp)
        );
        assert_eq!(
            format_from_extension("test.ico"),
            Some(ImageFormatType::Ico)
        );
        assert_eq!(format_from_extension("test.unknown"), None);
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1024), "1.00 KB");
        assert_eq!(format_file_size(1536), "1.50 KB");
        assert_eq!(format_file_size(1048576), "1.00 MB");
    }
}
