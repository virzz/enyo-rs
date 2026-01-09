//! ICO icon generation

use anyhow::{Context, Result};
use image::GenericImageView;
use std::{fs::File, io::Cursor, path::Path};

use super::{types::ResizeFilter, utils::load_image};

/// ICO 标准尺寸
const ICO_STANDARD_SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256];

/// 生成 ICO 图标
pub fn generate_icon(
    input: &str,
    output: Option<&str>,
    auto_resize: bool,
    sizes: Option<Vec<u32>>,
    filter: ResizeFilter,
) -> Result<String> {
    let img = load_image(input)?;

    // 确定要生成的尺寸
    let target_sizes: Vec<u32> = if auto_resize {
        ICO_STANDARD_SIZES.to_vec()
    } else if let Some(custom_sizes) = sizes {
        custom_sizes
    } else {
        // 默认使用原始尺寸
        let (w, h) = img.dimensions();
        vec![w.min(h).min(256)]
    };

    // 确定输出路径
    let output_path = match output {
        Some(path) => path.to_string(),
        None => {
            let input_path = Path::new(input);
            let stem = input_path
                .file_stem()
                .unwrap_or_default()
                .to_str()
                .unwrap_or("icon");
            format!("{}.ico", stem)
        }
    };

    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);

    for size in &target_sizes {
        let size = *size;
        if size > 256 {
            eprintln!("警告: ICO 格式最大支持 256x256，跳过尺寸 {}x{}", size, size);
            continue;
        }

        let resized = img.resize_exact(size, size, filter.into());
        let rgba_img = resized.to_rgba8();

        // 编码为 PNG
        let mut png_data = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(Cursor::new(&mut png_data));
        rgba_img.write_with_encoder(encoder)?;

        let icon_image = ico::IconImage::read_png(Cursor::new(&png_data))?;
        icon_dir.add_entry(ico::IconDirEntry::encode(&icon_image)?);
    }

    let output_file = File::create(&output_path)
        .with_context(|| format!("无法创建 ICO 文件: {}", output_path))?;
    icon_dir.write(output_file)?;

    let sizes_str: Vec<String> = target_sizes
        .iter()
        .map(|s| format!("{}x{}", s, s))
        .collect();
    Ok(format!(
        "ICO 生成完成: {}\n包含尺寸: {}\n输出文件: {}",
        input,
        sizes_str.join(", "),
        output_path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use tempfile::TempDir;

    fn create_test_image(path: &str, width: u32, height: u32) -> Result<()> {
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(width, height, |x, y| {
            Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
        });
        img.save(path)?;
        Ok(())
    }

    #[test]
    fn test_generate_icon_single_size() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");
        let output_path = temp_dir.path().join("test.ico");

        create_test_image(input_path.to_str().unwrap(), 64, 64)?;

        let result = generate_icon(
            input_path.to_str().unwrap(),
            Some(output_path.to_str().unwrap()),
            false,
            None,
            ResizeFilter::Nearest,
        )?;

        assert!(result.contains("ICO 生成完成"));
        assert!(output_path.exists());
        Ok(())
    }

    #[test]
    fn test_generate_icon_auto_resize() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");
        let output_path = temp_dir.path().join("test.ico");

        create_test_image(input_path.to_str().unwrap(), 256, 256)?;

        let result = generate_icon(
            input_path.to_str().unwrap(),
            Some(output_path.to_str().unwrap()),
            true,
            None,
            ResizeFilter::Nearest,
        )?;

        assert!(result.contains("ICO 生成完成"));
        assert!(result.contains("16x16"));
        assert!(result.contains("32x32"));
        assert!(result.contains("256x256"));
        assert!(output_path.exists());
        Ok(())
    }

    #[test]
    fn test_generate_icon_custom_sizes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");
        let output_path = temp_dir.path().join("test.ico");

        create_test_image(input_path.to_str().unwrap(), 128, 128)?;

        let result = generate_icon(
            input_path.to_str().unwrap(),
            Some(output_path.to_str().unwrap()),
            false,
            Some(vec![16, 32, 64]),
            ResizeFilter::Nearest,
        )?;

        assert!(result.contains("ICO 生成完成"));
        assert!(result.contains("16x16"));
        assert!(result.contains("32x32"));
        assert!(result.contains("64x64"));
        assert!(output_path.exists());
        Ok(())
    }

    #[test]
    fn test_generate_icon_default_output_name() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("myicon.png");

        create_test_image(input_path.to_str().unwrap(), 64, 64)?;

        let result = generate_icon(
            input_path.to_str().unwrap(),
            None,
            false,
            Some(vec![32]),
            ResizeFilter::Nearest,
        )?;

        assert!(result.contains("ICO 生成完成"));
        assert!(result.contains("myicon.ico"));
        Ok(())
    }
}
