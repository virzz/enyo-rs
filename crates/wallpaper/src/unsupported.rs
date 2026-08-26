use std::path::Path;

use anyhow::{bail, Result};

use super::{WallpaperFolder, YourPhotosContents};

/// Cross-platform placeholder. Wallpaper mutation is currently implemented only on macOS.
pub struct WallpaperManager {
    _private: (),
}

impl WallpaperManager {
    pub fn new() -> Result<Self> {
        bail!("wallpaper is currently supported only on macOS")
    }

    pub fn add_folder(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn remove_folder(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn list_folders(&self) -> Result<Vec<WallpaperFolder>> {
        unsupported()
    }

    pub fn is_folder_registered(&self, _path: &str) -> Result<bool> {
        unsupported()
    }

    pub fn add_photo(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn remove_photo(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn list_photos(&self) -> Result<Vec<WallpaperFolder>> {
        unsupported()
    }

    pub fn your_photos_contents(&self) -> Result<YourPhotosContents> {
        unsupported()
    }

    pub fn reset_your_photos(&self, _include_folders: bool) -> Result<YourPhotosContents> {
        unsupported()
    }

    pub fn restart_services(&self) -> Result<()> {
        unsupported()
    }

    pub fn add_folder_and_apply(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn remove_folder_and_apply(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn add_photo_and_apply(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn remove_photo_and_apply(&self, _path: &str) -> Result<()> {
        unsupported()
    }

    pub fn reset_your_photos_and_apply(
        &self,
        _include_folders: bool,
    ) -> Result<YourPhotosContents> {
        unsupported()
    }

    pub fn os_version(&self) -> &str {
        "unsupported"
    }

    pub fn mode_description(&self) -> &str {
        "unsupported"
    }

    pub fn is_tahoe_or_later(&self) -> bool {
        false
    }

    pub fn plist_path(&self) -> &Path {
        Path::new("")
    }

    pub fn cache_base_path(&self) -> Option<&Path> {
        None
    }
}

fn unsupported<T>() -> Result<T> {
    bail!("wallpaper is currently supported only on macOS")
}
