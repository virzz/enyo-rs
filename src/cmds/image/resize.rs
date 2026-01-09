//! Image resizing operations

use anyhow::{anyhow, Result};
use image::GenericImageView;
use std::path::Path;

use super::{types::ResizeFilter, utils::load_image};

/// 图片缩放
pub fn resize_image(
    input: &str,
    output: Option<&str>,
    width: Option<u32>,
    height: Option<u32>,
    scale: Option<f32>,
    filter: ResizeFilter,
    keep_aspect: bool,
) -> Result<String> {
    let img = load_image(input)?;
    let (orig_width, orig_height) = img.dimensions();

    // 计算目标尺寸
    let (target_width, target_height) = if let Some(scale_percent) = scale {
        let scale_factor = scale_percent / 100.0;
        (
            (orig_width as f32 * scale_factor) as u32,
            (orig_height as f32 * scale_factor) as u32,
        )
    } else {
        match (width, height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => {
                if keep_aspect {
                    let w_ratio = w as f32 / orig_width as f32;
                    let h_ratio = h as f32 / orig_height as f32;
                    let ratio = w_ratio.min(h_ratio);
                    (
                        (orig_width as f32 * ratio) as u32,
                        (orig_height as f32 * ratio) as u32,
                    )
                } else {
                    (w, h)
                }
            }
            (Some(w), _) if w > 0 => {
                let ratio = w as f32 / orig_width as f32;
                (w, (orig_height as f32 * ratio) as u32)
            }
            (_, Some(h)) if h > 0 => {
                let ratio = h as f32 / orig_height as f32;
                ((orig_width as f32 * ratio) as u32, h)
            }
            _ => return Err(anyhow!("请指定宽度、高度或缩放比例")),
        }
    };

    let resized = img.resize_exact(target_width, target_height, filter.into());

    // 确定输出路径
    let output_path = match output {
        Some(path) => path.to_string(),
        None => {
            let input_path = Path::new(input);
            let stem = input_path
                .file_stem()
                .unwrap_or_default()
                .to_str()
                .unwrap_or("output");
            let ext = input_path
                .extension()
                .unwrap_or_default()
                .to_str()
                .unwrap_or("png");
            format!("{}_{}x{}.{}", stem, target_width, target_height, ext)
        }
    };

    resized.save(&output_path)?;
    Ok(format!(
        "缩放完成: {}x{} -> {}x{}\n输出文件: {}",
        orig_width, orig_height, target_width, target_height, output_path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use tempfile::TempDir;

    fn create_test_image(path: &str, width: u32, height: u32) -> Result<()> {
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(width, height, |x, y| {
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
    fn test_resize_by_width() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");
        let output_path = temp_dir.path().join("resized.png");

        create_test_image(input_path.to_str().unwrap(), 200, 100)?;

        let result = resize_image(
            input_path.to_str().unwrap(),
            Some(output_path.to_str().unwrap()),
            Some(100),
            None,
            None,
            ResizeFilter::Nearest,
            true,
        )?;

        assert!(result.contains("缩放完成"));
        assert!(result.contains("100x50"));
        assert!(output_path.exists());
        Ok(())
    }

    #[test]
    fn test_resize_by_scale() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");

        create_test_image(input_path.to_str().unwrap(), 200, 100)?;

        let result = resize_image(
            input_path.to_str().unwrap(),
            None,
            None,
            None,
            Some(50.0),
            ResizeFilter::Nearest,
            true,
        )?;

        assert!(result.contains("缩放完成"));
        assert!(result.contains("100x50"));
        Ok(())
    }

    #[test]
    fn test_resize_with_both_dimensions() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");

        create_test_image(input_path.to_str().unwrap(), 200, 100)?;

        let result = resize_image(
            input_path.to_str().unwrap(),
            None,
            Some(100),
            Some(100),
            None,
            ResizeFilter::Nearest,
            false,
        )?;

        assert!(result.contains("缩放完成"));
        assert!(result.contains("100x100"));
        Ok(())
    }

    #[test]
    fn test_resize_keep_aspect_ratio() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");

        create_test_image(input_path.to_str().unwrap(), 200, 100)?;

        let result = resize_image(
            input_path.to_str().unwrap(),
            None,
            Some(100),
            Some(100),
            None,
            ResizeFilter::Nearest,
            true,
        )?;

        assert!(result.contains("缩放完成"));
        // 保持宽高比，应该是 100x50
        assert!(result.contains("100x50"));
        Ok(())
    }

    #[test]
    fn test_resize_no_dimensions() {
        let temp_dir = TempDir::new().unwrap();
        let input_path = temp_dir.path().join("test.png");

        create_test_image(input_path.to_str().unwrap(), 200, 100).unwrap();

        let result = resize_image(
            input_path.to_str().unwrap(),
            None,
            None,
            None,
            None,
            ResizeFilter::Nearest,
            true,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("请指定宽度、高度或缩放比例"));
    }
}
