//! @alias: img
//! @about: Image processing tools (convert, resize, icon, exif)

mod convert;
mod exif;
mod icon;
mod info;
mod resize;
mod types;
mod utils;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::CmdExecute;
pub use types::{ImageFormatType, ResizeFilter};

#[derive(Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    command: SubCmd,
}

#[derive(Subcommand)]
pub enum SubCmd {
    /// Convert image format (jpg, png, webp, ico, bmp, gif, tiff)
    #[clap(alias = "conv", alias = "c")]
    Convert {
        /// Input image file path
        #[arg(short, long)]
        input: String,

        /// Output file path (required, format auto-detected from extension)
        #[arg(short, long)]
        output: String,

        /// JPEG quality (1-100, only for JPEG format)
        #[arg(short, long, default_value = "90")]
        quality: u8,
    },

    /// Resize image to specified dimensions
    #[clap(alias = "rs")]
    Resize {
        /// Input image file path
        #[arg(short, long)]
        input: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Target width (use 0 or skip to auto-calculate from height)
        #[arg(short, long)]
        width: Option<u32>,

        /// Target height (use 0 or skip to auto-calculate from width)
        #[arg(short = 'H', long)]
        height: Option<u32>,

        /// Scale percentage (e.g., 50 for 50%)
        #[arg(short, long)]
        scale: Option<f32>,

        /// Resize filter algorithm
        #[arg(short, long, value_enum, default_value = "catmull-rom")]
        filter: ResizeFilter,

        /// Keep aspect ratio (default: true)
        #[arg(short, long, default_value = "true")]
        aspect: bool,
    },

    /// Generate ICO file from image with multiple sizes
    #[clap(alias = "ico")]
    Icon {
        /// Input image file path
        #[arg(short, long)]
        input: String,

        /// Output ICO file path
        #[arg(short, long)]
        output: Option<String>,

        /// Auto-resize: generate all standard ICO sizes (16, 24, 32, 48, 64, 128, 256)
        #[arg(short, long, default_value = "false")]
        auto_resize: bool,

        /// Custom sizes to include (comma-separated or multiple values)
        #[arg(short, long, value_delimiter = ',')]
        sizes: Option<Vec<u32>>,

        /// Resize filter algorithm
        #[arg(short, long, value_enum, default_value = "lanczos3")]
        filter: ResizeFilter,
    },

    /// Read EXIF metadata from image
    #[clap(alias = "er")]
    ExifRead {
        /// Input image file path
        target: String,

        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Show all fields including unknown tags
        #[arg(short, long)]
        all: bool,
    },

    /// Strip EXIF metadata from image
    #[clap(alias = "es")]
    ExifStrip {
        /// Input image file path
        #[arg(short, long)]
        input: String,

        /// Output file path (overwrites input if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Get image information (dimensions, format, etc.)
    #[clap(alias = "i")]
    Info {
        /// Input image file path
        target: String,
    },
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        let result = match &self.command {
            SubCmd::Convert {
                input,
                output,
                quality,
            } => convert::convert_image(input, output, *quality)?,

            SubCmd::Resize {
                input,
                output,
                width,
                height,
                scale,
                filter,
                aspect,
            } => resize::resize_image(
                input,
                output.as_deref(),
                *width,
                *height,
                *scale,
                *filter,
                *aspect,
            )?,

            SubCmd::Icon {
                input,
                output,
                auto_resize,
                sizes,
                filter,
            } => icon::generate_icon(
                input,
                output.as_deref(),
                *auto_resize,
                sizes.clone(),
                *filter,
            )?,

            SubCmd::ExifRead {
                target,
                format,
                all,
            } => exif::read_exif(target, format, *all)?,

            SubCmd::ExifStrip { input, output } => exif::strip_exif(input, output.as_deref())?,

            SubCmd::Info { target } => info::get_image_info(target)?,
        };

        println!("{}", result);
        Ok(())
    }
}
