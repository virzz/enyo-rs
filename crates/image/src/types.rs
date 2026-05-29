//! Image format types and filter definitions

use clap::ValueEnum;
use image::{imageops::FilterType, ImageFormat};

/// 支持的图片格式
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum ImageFormatType {
    /// PNG 格式
    Png,
    /// JPEG 格式
    Jpg,
    /// WebP 格式
    Webp,
    /// ICO 格式
    Ico,
    /// BMP 格式
    Bmp,
    /// GIF 格式
    Gif,
    /// TIFF 格式
    Tiff,
}

impl ImageFormatType {
    // /// 获取文件扩展名
    // pub fn extension(&self) -> &'static str {
    //     match self {
    //         ImageFormatType::Jpg => "jpg",
    //         ImageFormatType::Png => "png",
    //         ImageFormatType::Webp => "webp",
    //         ImageFormatType::Ico => "ico",
    //         ImageFormatType::Bmp => "bmp",
    //         ImageFormatType::Gif => "gif",
    //         ImageFormatType::Tiff => "tiff",
    //     }
    // }

    /// 转换为 image crate 的 ImageFormat
    pub fn to_image_format(self) -> Option<ImageFormat> {
        match self {
            ImageFormatType::Png => Some(ImageFormat::Png),
            ImageFormatType::Jpg => Some(ImageFormat::Jpeg),
            ImageFormatType::Gif => Some(ImageFormat::Gif),
            ImageFormatType::Webp => Some(ImageFormat::WebP),
            ImageFormatType::Tiff => Some(ImageFormat::Tiff),
            ImageFormatType::Bmp => Some(ImageFormat::Bmp),
            ImageFormatType::Ico => Some(ImageFormat::Ico),
        }
    }
}

/// 缩放滤波器类型
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ResizeFilter {
    /// 最近邻插值 (最快，质量最低)
    Nearest,
    /// 三角形/双线性插值
    Triangle,
    /// CatmullRom 插值 (平衡速度和质量)
    #[default]
    CatmullRom,
    /// 高斯插值
    Gaussian,
    /// Lanczos3 插值 (最慢，质量最高)
    Lanczos3,
}

impl From<ResizeFilter> for FilterType {
    fn from(filter: ResizeFilter) -> Self {
        match filter {
            ResizeFilter::Nearest => FilterType::Nearest,
            ResizeFilter::Triangle => FilterType::Triangle,
            ResizeFilter::CatmullRom => FilterType::CatmullRom,
            ResizeFilter::Gaussian => FilterType::Gaussian,
            ResizeFilter::Lanczos3 => FilterType::Lanczos3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_image_format_extension() {
    //     assert_eq!(ImageFormatType::Jpg.extension(), "jpg");
    //     assert_eq!(ImageFormatType::Png.extension(), "png");
    //     assert_eq!(ImageFormatType::Webp.extension(), "webp");
    //     assert_eq!(ImageFormatType::Ico.extension(), "ico");
    //     assert_eq!(ImageFormatType::Bmp.extension(), "bmp");
    //     assert_eq!(ImageFormatType::Gif.extension(), "gif");
    //     assert_eq!(ImageFormatType::Tiff.extension(), "tiff");
    // }

    #[test]
    fn test_image_format_to_image_format() {
        assert_eq!(
            ImageFormatType::Jpg.to_image_format(),
            Some(ImageFormat::Jpeg)
        );
        assert_eq!(
            ImageFormatType::Png.to_image_format(),
            Some(ImageFormat::Png)
        );
        assert_eq!(
            ImageFormatType::Webp.to_image_format(),
            Some(ImageFormat::WebP)
        );
        assert_eq!(
            ImageFormatType::Ico.to_image_format(),
            Some(ImageFormat::Ico)
        );
    }

    #[test]
    fn test_resize_filter_conversion() {
        let filter: FilterType = ResizeFilter::Nearest.into();
        assert!(matches!(filter, FilterType::Nearest));

        let filter: FilterType = ResizeFilter::Lanczos3.into();
        assert!(matches!(filter, FilterType::Lanczos3));

        let filter: FilterType = ResizeFilter::CatmullRom.into();
        assert!(matches!(filter, FilterType::CatmullRom));
    }

    #[test]
    fn test_resize_filter_default() {
        let default_filter = ResizeFilter::default();
        assert!(matches!(default_filter, ResizeFilter::CatmullRom));
    }
}
