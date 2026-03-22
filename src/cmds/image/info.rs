//! Image information display

use anyhow::Result;
use image::{GenericImageView, ImageReader};
use std::{fs, fs::File, io::BufReader};

use super::utils::{format_file_size, load_image};

/// 获取图片信息
pub fn get_image_info(target: &str) -> Result<String> {
    let img = load_image(target)?;
    let (width, height) = img.dimensions();

    let file_metadata = fs::metadata(target)?;
    let file_size = file_metadata.len();

    let format = ImageReader::open(target)?
        .with_guessed_format()?
        .format()
        .map(|f| format!("{:?}", f))
        .unwrap_or_else(|| "Unknown".to_string());

    let color_type = format!("{:?}", img.color());

    // 尝试读取 EXIF 信息
    let exif_info = {
        let file = File::open(target).ok();
        file.and_then(|f| {
            let mut reader = BufReader::new(f);
            let exif_reader = exif::Reader::new();
            exif_reader.read_from_container(&mut reader).ok()
        })
    };

    let has_exif = exif_info.is_some();
    let exif_count = exif_info.map(|e| e.fields().count()).unwrap_or(0);

    use comfy_table::{presets::UTF8_FULL, Table};
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Property", "Value"]);
    table.add_row(vec!["File", target]);
    table.add_row(vec!["Format", &format]);
    table.add_row(vec!["Dimensions", &format!("{}x{}", width, height)]);
    table.add_row(vec!["Color Type", &color_type]);
    table.add_row(vec!["File Size", &format_file_size(file_size)]);
    table.add_row(vec!["Has EXIF", &has_exif.to_string()]);
    if has_exif {
        table.add_row(vec!["EXIF Fields", &exif_count.to_string()]);
    }

    Ok(table.to_string())
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
    fn test_get_image_info() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.png");

        create_test_image(input_path.to_str().unwrap(), 200, 150)?;

        let result = get_image_info(input_path.to_str().unwrap())?;

        assert!(result.contains("200x150"));
        assert!(result.contains("Png"));
        assert!(result.contains("File Size"));
        assert!(result.contains("Has EXIF"));
        Ok(())
    }

    #[test]
    fn test_get_image_info_different_format() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let input_path = temp_dir.path().join("test.jpg");

        create_test_image(input_path.to_str().unwrap(), 100, 100)?;

        let result = get_image_info(input_path.to_str().unwrap())?;

        assert!(result.contains("100x100"));
        assert!(result.contains("Jpeg"));
        Ok(())
    }

    #[test]
    fn test_get_image_info_nonexistent_file() {
        let result = get_image_info("nonexistent.jpg");
        assert!(result.is_err());
    }
}
