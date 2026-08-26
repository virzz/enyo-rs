//! @alias: wp
//! @alias: wallpaper-folder
//! @about: Manage macOS System Settings wallpaper folders and photos

use std::{path::PathBuf, time::SystemTime};

use anyhow::Result;
use clap::{Parser, Subcommand};
use enyo_core::Action;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod unsupported;

#[cfg(target_os = "macos")]
pub use macos::WallpaperManager;
#[cfg(not(target_os = "macos"))]
pub use unsupported::WallpaperManager;

/// A wallpaper folder registered in System Settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallpaperFolder {
    pub id: Option<String>,
    pub path: PathBuf,
    pub date_added: Option<SystemTime>,
}

/// Counts of the sources contributing to the macOS "Your Photos" section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct YourPhotosContents {
    pub image_files: usize,
    pub image_folders: usize,
    pub assets: usize,
    pub collections: usize,
    pub people: usize,
}

impl YourPhotosContents {
    pub fn total(self) -> usize {
        self.image_files + self.image_folders + self.assets + self.collections + self.people
    }
}

/// Manage wallpaper sources in macOS System Settings.
#[derive(Debug, Parser)]
#[command(name = "wallpaper")]
pub struct Cmd {
    #[command(subcommand)]
    command: SubCmd,
}

#[derive(Debug, Subcommand)]
enum SubCmd {
    /// Add a folder to System Settings wallpaper sources
    #[command(alias = "a")]
    Add {
        /// Path to the folder containing images
        folder: String,

        /// Do not restart wallpaper services after adding
        #[arg(short, long)]
        no_restart: bool,

        /// Show the macOS version, storage mode, and plist path
        #[arg(short, long)]
        verbose: bool,
    },

    /// Remove a folder from System Settings wallpaper sources
    #[command(alias = "rm")]
    Remove {
        /// Path to the registered folder
        folder: String,

        /// Do not restart wallpaper services after removing
        #[arg(short, long)]
        no_restart: bool,

        /// Show the macOS version, storage mode, and plist path
        #[arg(short, long)]
        verbose: bool,
    },

    /// List registered wallpaper folders
    #[command(alias = "ls")]
    List {
        /// Include IDs, dates, and the plist path
        #[arg(short, long)]
        verbose: bool,
    },

    /// Add an image to "Your Photos" (macOS 26+)
    #[command(alias = "ap")]
    AddPhoto {
        /// Path to the image file
        image: String,

        /// Do not restart wallpaper services after adding
        #[arg(short, long)]
        no_restart: bool,

        /// Show the macOS version, storage mode, and plist path
        #[arg(short, long)]
        verbose: bool,
    },

    /// Remove an image from "Your Photos" (macOS 26+)
    #[command(alias = "rmp")]
    RemovePhoto {
        /// Path to the registered image file
        image: String,

        /// Do not restart wallpaper services after removing
        #[arg(short, long)]
        no_restart: bool,

        /// Show the macOS version, storage mode, and plist path
        #[arg(short, long)]
        verbose: bool,
    },

    /// List individual images in "Your Photos" (macOS 26+)
    #[command(alias = "lsp")]
    ListPhotos {
        /// Include the plist path
        #[arg(short, long)]
        verbose: bool,
    },

    /// Clear the "Your Photos" sources (macOS 26+)
    #[command(alias = "rsp")]
    ResetPhotos {
        /// Also remove custom wallpaper folders
        #[arg(long)]
        include_folders: bool,

        /// Do not restart wallpaper services after clearing
        #[arg(short, long)]
        no_restart: bool,

        /// Show the macOS version, storage mode, and plist path
        #[arg(short, long)]
        verbose: bool,
    },
}

impl Action for Cmd {
    fn execute(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        std::future::ready(self.execute_sync())
    }
}

impl Cmd {
    fn execute_sync(&self) -> Result<()> {
        let manager = WallpaperManager::new()?;

        match &self.command {
            SubCmd::Add {
                folder,
                no_restart,
                verbose,
            } => {
                print_version_info(&manager, *verbose);
                manager.add_folder(folder)?;
                apply_change(&manager, *no_restart)?;
                println!("Added wallpaper folder: {}", display_path(folder));
            }
            SubCmd::Remove {
                folder,
                no_restart,
                verbose,
            } => {
                print_version_info(&manager, *verbose);
                manager.remove_folder(folder)?;
                apply_change(&manager, *no_restart)?;
                println!("Removed wallpaper folder: {}", display_path(folder));
            }
            SubCmd::List { verbose } => {
                print_version_info(&manager, *verbose);
                let folders = manager.list_folders()?;
                if folders.is_empty() {
                    println!("No wallpaper folders configured.");
                } else {
                    println!("Registered wallpaper folders ({}):", folders.len());
                    for (index, folder) in folders.iter().enumerate() {
                        println!("  {}. {}", index + 1, folder.path.display());
                        if *verbose {
                            if let Some(id) = &folder.id {
                                println!("     ID: {id}");
                            }
                            if let Some(date) = folder.date_added {
                                println!("     Added: {}", plist::Date::from(date).to_xml_format());
                            }
                        }
                    }
                }
            }
            SubCmd::AddPhoto {
                image,
                no_restart,
                verbose,
            } => {
                print_version_info(&manager, *verbose);
                manager.add_photo(image)?;
                apply_change(&manager, *no_restart)?;
                println!("Added photo: {}", display_path(image));
            }
            SubCmd::RemovePhoto {
                image,
                no_restart,
                verbose,
            } => {
                print_version_info(&manager, *verbose);
                manager.remove_photo(image)?;
                apply_change(&manager, *no_restart)?;
                println!("Removed photo: {}", display_path(image));
            }
            SubCmd::ListPhotos { verbose } => {
                print_version_info(&manager, *verbose);
                let photos = manager.list_photos()?;
                if photos.is_empty() {
                    println!("No individual photos in 'Your Photos'.");
                } else {
                    println!("Photos in 'Your Photos' ({}):", photos.len());
                    for (index, photo) in photos.iter().enumerate() {
                        println!("  {}. {}", index + 1, photo.path.display());
                    }
                }
            }
            SubCmd::ResetPhotos {
                include_folders,
                no_restart,
                verbose,
            } => {
                print_version_info(&manager, *verbose);
                let before = manager.reset_your_photos(*include_folders)?;
                apply_change(&manager, *no_restart)?;
                println!("Cleared 'Your Photos':");
                println!("  Individual images: {}", before.image_files);
                println!("  Photos assets:     {}", before.assets);
                println!("  Photos albums:     {}", before.collections);
                println!("  Photos people:     {}", before.people);
                if *include_folders {
                    println!("  Custom folders:    {}", before.image_folders);
                } else if before.image_folders > 0 {
                    println!(
                        "  Custom folders left in place: {} (use --include-folders to remove)",
                        before.image_folders
                    );
                }
            }
        }

        Ok(())
    }
}

fn apply_change(manager: &WallpaperManager, no_restart: bool) -> Result<()> {
    if no_restart {
        println!("Run 'killall cfprefsd; killall WallpaperAgent' to apply changes.");
        Ok(())
    } else {
        manager.restart_services()
    }
}

fn print_version_info(manager: &WallpaperManager, verbose: bool) {
    if verbose {
        println!(
            "macOS {} - Using {} mode",
            manager.os_version(),
            manager.mode_description()
        );
        println!("Plist: {}", manager.plist_path().display());
    }
}

fn display_path(path: &str) -> String {
    dirs::home_dir()
        .and_then(|home| {
            path.strip_prefix("~/")
                .map(|suffix| home.join(suffix).display().to_string())
        })
        .unwrap_or_else(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_all_subcommands() {
        for args in [
            vec!["wallpaper", "add", "/tmp/images", "--no-restart"],
            vec!["wallpaper", "remove", "/tmp/images"],
            vec!["wallpaper", "list", "--verbose"],
            vec!["wallpaper", "add-photo", "/tmp/a.jpg"],
            vec!["wallpaper", "remove-photo", "/tmp/a.jpg"],
            vec!["wallpaper", "list-photos"],
            vec!["wallpaper", "reset-photos", "--include-folders"],
        ] {
            Cmd::try_parse_from(args).unwrap();
        }
    }

    #[test]
    fn parses_subcommand_aliases() {
        for args in [
            vec!["wallpaper", "a", "/tmp/images"],
            vec!["wallpaper", "rm", "/tmp/images"],
            vec!["wallpaper", "ls"],
            vec!["wallpaper", "ap", "/tmp/a.jpg"],
            vec!["wallpaper", "rmp", "/tmp/a.jpg"],
            vec!["wallpaper", "lsp"],
            vec!["wallpaper", "rsp"],
        ] {
            Cmd::try_parse_from(args).unwrap();
        }
    }

    #[test]
    fn contents_total_sums_all_sources() {
        let contents = YourPhotosContents {
            image_files: 1,
            image_folders: 2,
            assets: 3,
            collections: 4,
            people: 5,
        };

        assert_eq!(contents.total(), 15);
    }
}
