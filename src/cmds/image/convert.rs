//! Image format conversion

use anyhow::{anyhow, Context, Result};
use image::RgbaImage;
use std::{
    fs::File,
    io::{BufWriter, Cursor},
};

use super::{
    types::ImageFormatType,
    utils::{format_from_extension, load_image},
};

/// 图片格式转换
pub fn convert_image(input: &str, output: &str, quality: u8) -> Result<String> {
    let img = load_image(input)?;

    // 从输出文件扩展名确定目标格式
    let target_format = format_from_extension(output)
        .ok_or_else(|| anyhow!("无法从输出文件扩展名识别格式: {}", output))?;

    // 保存图片
    match target_format {
        ImageFormatType::Jpg => {
            let rgb_img = img.to_rgb8();
            let mut output_file = BufWriter::new(
                File::create(output).with_context(|| format!("无法创建输出文件: {}", output))?,
            );
            let encoder =
                image::codecs::jpeg::JpegEncoder::new_with_quality(&mut output_file, quality);
            rgb_img.write_with_encoder(encoder)?;
        }
        ImageFormatType::Ico => {
            // ICO 格式需要特殊处理，转换为 PNG 中间格式
            let rgba_img = img.to_rgba8();
            save_ico_single(&rgba_img, output)?;
        }
        _ => {
            let image_format = target_format
                .to_image_format()
                .ok_or_else(|| anyhow!("不支持的格式: {:?}", target_format))?;
            img.save_with_format(output, image_format)?;
        }
    }

    Ok(format!("转换完成: {} -> {}", input, output))
}

/// 保存单个图片为 ICO
fn save_ico_single(img: &RgbaImage, output_path: &str) -> Result<()> {
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);

    // 将图片编码为 PNG 格式
    let mut png_data = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(Cursor::new(&mut png_data));
    img.write_with_encoder(encoder)?;

    let icon_image = ico::IconImage::read_png(Cursor::new(&png_data))?;
    icon_dir.add_entry(ico::IconDirEntry::encode(&icon_image)?);

    let output_file =
        File::create(output_path).with_context(|| format!("无法创建 ICO 文件: {}", output_path))?;
    icon_dir.write(output_file)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use tempfile::TempDir;

    fn create_test_image(path: &str, width: u32, height: u32) -> Result<()> {
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(width, height, |x, y| {
            if (x + y) % 2 == 0 {
                Rgb([255, 0, 0])
            } else {
                Rgb([0, 0, 255])
            }
        });
        img.save(path)?;
        Ok(())
    }

    #[test]
    fn test_convert_png_to_jpg() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");
        let output_path = temp_dir.path().join("test.jpg");

        create_test_image(input_path.to_str().unwrap(), 100, 100)?;

        let result = convert_image(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            90,
        )?;

        assert!(result.contains("转换完成"));
        assert!(output_path.exists());
        Ok(())
    }

    #[test]
    fn test_convert_with_invalid_output_format() {
        let temp_dir = TempDir::new().unwrap();
        let input_path = temp_dir.path().join("test.png");
        let output_path = temp_dir.path().join("test.unknown");

        create_test_image(input_path.to_str().unwrap(), 100, 100).unwrap();

        let result = convert_image(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            90,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("无法从输出文件扩展名识别格式"));
    }

    #[test]
    fn test_convert_nonexistent_file() {
        let result = convert_image("nonexistent.png", "output.jpg", 90);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_ico_single() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_path = temp_dir.path().join("test.ico");

        let img: ImageBuffer<image::Rgba<u8>, Vec<u8>> = ImageBuffer::from_fn(32, 32, |x, y| {
            if (x + y) % 2 == 0 {
                image::Rgba([255, 0, 0, 255])
            } else {
                image::Rgba([0, 0, 255, 255])
            }
        });

        save_ico_single(&img, output_path.to_str().unwrap())?;
        assert!(output_path.exists());
        Ok(())
    }
}
