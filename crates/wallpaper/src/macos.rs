use std::{
    env, fs,
    io::Cursor,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    ptr,
    time::SystemTime,
};

use anyhow::{anyhow, bail, Context, Result};
use core_foundation::{
    base::{kCFAllocatorDefault, TCFType},
    data::CFData,
    error::{CFError, CFErrorRef},
    propertylist::{
        create_data, create_with_data, kCFPropertyListBinaryFormat_v1_0, kCFPropertyListImmutable,
        CFPropertyList,
    },
    string::CFString,
    url::{kCFURLBookmarkCreationMinimalBookmarkMask, CFURLCreateBookmarkData, CFURL},
};
use core_foundation_sys::preferences::{
    CFPreferencesAppSynchronize, CFPreferencesCopyAppValue, CFPreferencesSetAppValue,
};
use plist::{Dictionary, Value};
use url::Url;
use uuid::Uuid;

use super::{WallpaperFolder, YourPhotosContents};

const LEGACY_DOMAIN: &str = "com.apple.systempreferences";
const LEGACY_PREF_PANE: &str = "DSKDesktopPrefPane";
const LEGACY_FOLDER_PATHS: &str = "UserFolderPaths";

const ASSETS: &str = "ChoiceRequests.Assets";
const COLLECTIONS: &str = "ChoiceRequests.CollectionIdentifiers";
const IMAGE_FILES: &str = "ChoiceRequests.ImageFiles";
const IMAGE_FOLDERS: &str = "ChoiceRequests.ImageFolders";
const PEOPLE: &str = "ChoiceRequests.PersonIdentifiers";
const MIGRATION_KEYS: [&str; 3] = [
    "DidPerformImagesContainerMigration",
    "DidPerformPhotosContainerMigration",
    "DidPerformPhotosMigration",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageMode {
    Legacy,
    Tahoe,
}

/// macOS wallpaper source manager compatible with Sequoia and Tahoe storage formats.
pub struct WallpaperManager {
    mode: StorageMode,
    os_version: String,
    plist_path: PathBuf,
    cache_base_path: Option<PathBuf>,
    use_defaults_domain: bool,
}

impl WallpaperManager {
    pub fn new() -> Result<Self> {
        let os_version = macos_version()?;
        let major_version = os_version
            .split('.')
            .next()
            .context("macOS version is empty")?
            .parse::<u32>()
            .with_context(|| format!("invalid macOS version: {os_version}"))?;
        let home = dirs::home_dir().context("failed to determine the home directory")?;

        if major_version >= 26 {
            Ok(Self {
                mode: StorageMode::Tahoe,
                os_version,
                plist_path: home.join(
                    "Library/Containers/com.apple.wallpaper.extension.image/Data/Library/Preferences/com.apple.wallpaper.extension.image.plist",
                ),
                cache_base_path: Some(user_cache_directory()?),
                use_defaults_domain: false,
            })
        } else {
            Ok(Self {
                mode: StorageMode::Legacy,
                os_version,
                plist_path: home.join("Library/Preferences/com.apple.systempreferences.plist"),
                cache_base_path: None,
                use_defaults_domain: true,
            })
        }
    }

    pub fn add_folder(&self, path: &str) -> Result<()> {
        let path = normalize_path(path)?;
        let metadata = fs::metadata(&path)
            .with_context(|| format!("wallpaper folder does not exist: {}", path.display()))?;
        if !metadata.is_dir() {
            bail!("not a directory: {}", path.display());
        }

        match self.mode {
            StorageMode::Legacy => self.add_folder_legacy(&path),
            StorageMode::Tahoe => self.add_folder_tahoe(&path),
        }
    }

    pub fn remove_folder(&self, path: &str) -> Result<()> {
        let path = normalize_path(path)?;
        match self.mode {
            StorageMode::Legacy => self.remove_folder_legacy(&path),
            StorageMode::Tahoe => self.remove_folder_tahoe(&path),
        }
    }

    pub fn list_folders(&self) -> Result<Vec<WallpaperFolder>> {
        match self.mode {
            StorageMode::Legacy => self.list_folders_legacy(),
            StorageMode::Tahoe => self.list_folders_tahoe(),
        }
    }

    pub fn is_folder_registered(&self, path: &str) -> Result<bool> {
        let path = normalize_path(path)?;
        Ok(self
            .list_folders()?
            .into_iter()
            .any(|folder| normalize_existing_path(&folder.path) == path))
    }

    pub fn add_photo(&self, path: &str) -> Result<()> {
        self.require_tahoe("adding individual photos")?;
        let path = normalize_path(path)?;
        let metadata = fs::metadata(&path)
            .with_context(|| format!("photo does not exist: {}", path.display()))?;
        if !metadata.is_file() {
            bail!("not a file: {}", path.display());
        }

        let mut root = self.load_tahoe_plist()?;
        if entry_paths(&root, IMAGE_FILES)?
            .any(|existing| normalize_existing_path(&existing) == path)
        {
            bail!("photo is already in 'Your Photos': {}", path.display());
        }

        let entry = self.create_tahoe_photo_entry(&path)?;
        array_mut(&mut root, IMAGE_FILES)?.push(Value::Data(entry));
        self.save_tahoe_plist(&mut root)
    }

    pub fn remove_photo(&self, path: &str) -> Result<()> {
        self.require_tahoe("removing individual photos")?;
        let path = normalize_path(path)?;
        let mut root = self.load_tahoe_plist()?;
        let entries = array_mut(&mut root, IMAGE_FILES)?;
        let original_len = entries.len();
        entries.retain(|entry| !entry_matches_path(entry, &path));
        if entries.len() == original_len {
            bail!("photo not found in 'Your Photos': {}", path.display());
        }

        self.save_tahoe_plist(&mut root)
    }

    pub fn list_photos(&self) -> Result<Vec<WallpaperFolder>> {
        if self.mode == StorageMode::Legacy {
            return Ok(Vec::new());
        }

        let root = self.load_tahoe_plist()?;
        let photos = entry_paths(&root, IMAGE_FILES)?
            .map(|path| WallpaperFolder {
                id: None,
                path,
                date_added: None,
            })
            .collect();
        Ok(photos)
    }

    pub fn your_photos_contents(&self) -> Result<YourPhotosContents> {
        self.require_tahoe("inspecting 'Your Photos'")?;
        let root = self.load_tahoe_plist()?;
        contents(&root)
    }

    pub fn reset_your_photos(&self, include_folders: bool) -> Result<YourPhotosContents> {
        self.require_tahoe("resetting 'Your Photos'")?;
        let mut root = self.load_tahoe_plist()?;
        let before = contents(&root)?;

        for key in [IMAGE_FILES, ASSETS, COLLECTIONS, PEOPLE] {
            array_mut(&mut root, key)?.clear();
        }
        if include_folders {
            array_mut(&mut root, IMAGE_FOLDERS)?.clear();
        }

        self.save_tahoe_plist(&mut root)?;
        Ok(before)
    }

    pub fn restart_services(&self) -> Result<()> {
        restart_process("cfprefsd")?;
        if self.mode == StorageMode::Tahoe {
            restart_process("WallpaperAgent")?;
        }
        Ok(())
    }

    pub fn add_folder_and_apply(&self, path: &str) -> Result<()> {
        self.add_folder(path)?;
        self.restart_services()
    }

    pub fn remove_folder_and_apply(&self, path: &str) -> Result<()> {
        self.remove_folder(path)?;
        self.restart_services()
    }

    pub fn add_photo_and_apply(&self, path: &str) -> Result<()> {
        self.add_photo(path)?;
        self.restart_services()
    }

    pub fn remove_photo_and_apply(&self, path: &str) -> Result<()> {
        self.remove_photo(path)?;
        self.restart_services()
    }

    pub fn reset_your_photos_and_apply(&self, include_folders: bool) -> Result<YourPhotosContents> {
        let before = self.reset_your_photos(include_folders)?;
        self.restart_services()?;
        Ok(before)
    }

    pub fn os_version(&self) -> &str {
        &self.os_version
    }

    pub fn mode_description(&self) -> &str {
        match self.mode {
            StorageMode::Legacy => "legacy UserFolderPaths",
            StorageMode::Tahoe => "Tahoe wallpaper extension",
        }
    }

    pub fn is_tahoe_or_later(&self) -> bool {
        self.mode == StorageMode::Tahoe
    }

    pub fn plist_path(&self) -> &Path {
        &self.plist_path
    }

    pub fn cache_base_path(&self) -> Option<&Path> {
        self.cache_base_path.as_deref()
    }

    fn require_tahoe(&self, operation: &str) -> Result<()> {
        if self.mode == StorageMode::Tahoe {
            Ok(())
        } else {
            bail!("{operation} requires macOS 26 (Tahoe) or later")
        }
    }

    fn add_folder_legacy(&self, path: &Path) -> Result<()> {
        let mut root = self.load_legacy_plist()?;
        let mut folders = legacy_folders(&root)?;
        if folders
            .iter()
            .any(|existing| normalize_existing_path(existing) == path)
        {
            bail!("wallpaper folder is already registered: {}", path.display());
        }

        folders.push(path.to_path_buf());
        set_legacy_folders(&mut root, &folders)?;
        self.save_legacy_plist(&root)
    }

    fn remove_folder_legacy(&self, path: &Path) -> Result<()> {
        let mut root = self.load_legacy_plist()?;
        let mut folders = legacy_folders(&root)?;
        let original_len = folders.len();
        folders.retain(|existing| normalize_existing_path(existing) != path);
        if folders.len() == original_len {
            bail!("wallpaper folder is not registered: {}", path.display());
        }

        set_legacy_folders(&mut root, &folders)?;
        self.save_legacy_plist(&root)
    }

    fn list_folders_legacy(&self) -> Result<Vec<WallpaperFolder>> {
        Ok(legacy_folders(&self.load_legacy_plist()?)?
            .into_iter()
            .map(|path| WallpaperFolder {
                id: None,
                path,
                date_added: None,
            })
            .collect())
    }

    fn load_legacy_plist(&self) -> Result<Dictionary> {
        if !self.use_defaults_domain {
            return load_dictionary_file(&self.plist_path, true);
        }

        let mut root = Dictionary::new();
        if let Some(pref_pane) = copy_preference_dictionary()? {
            root.insert(LEGACY_PREF_PANE.into(), Value::Dictionary(pref_pane));
        }
        Ok(root)
    }

    fn save_legacy_plist(&self, root: &Dictionary) -> Result<()> {
        if !self.use_defaults_domain {
            return save_dictionary_file(&self.plist_path, root);
        }

        let pref_pane = root
            .get(LEGACY_PREF_PANE)
            .and_then(Value::as_dictionary)
            .context("DSKDesktopPrefPane is not a dictionary")?;
        set_preference_dictionary(pref_pane)
    }

    fn add_folder_tahoe(&self, path: &Path) -> Result<()> {
        let mut root = self.load_tahoe_plist()?;
        if entry_paths(&root, IMAGE_FOLDERS)?
            .any(|existing| normalize_existing_path(&existing) == path)
        {
            bail!("wallpaper folder is already registered: {}", path.display());
        }

        let entry = self.create_tahoe_folder_entry(path)?;
        array_mut(&mut root, IMAGE_FOLDERS)?.push(Value::Data(entry));
        self.save_tahoe_plist(&mut root)
    }

    fn remove_folder_tahoe(&self, path: &Path) -> Result<()> {
        let mut root = self.load_tahoe_plist()?;
        let entries = array_mut(&mut root, IMAGE_FOLDERS)?;
        let original_len = entries.len();
        entries.retain(|entry| !entry_matches_path(entry, path));
        if entries.len() == original_len {
            bail!("wallpaper folder is not registered: {}", path.display());
        }

        self.save_tahoe_plist(&mut root)
    }

    fn list_folders_tahoe(&self) -> Result<Vec<WallpaperFolder>> {
        let root = self.load_tahoe_plist()?;
        let mut folders = Vec::new();
        for value in array(&root, IMAGE_FOLDERS)?.unwrap_or_default() {
            let Some(data) = value.as_data() else {
                continue;
            };
            let Ok(entry) = parse_dictionary(data, "wallpaper folder entry") else {
                continue;
            };
            let Ok(path) = original_path(&entry) else {
                continue;
            };
            folders.push(WallpaperFolder {
                id: entry
                    .get("id")
                    .and_then(Value::as_string)
                    .map(ToOwned::to_owned),
                path,
                date_added: entry
                    .get("dateAdded")
                    .and_then(Value::as_date)
                    .map(Into::into),
            });
        }
        Ok(folders)
    }

    fn create_tahoe_folder_entry(&self, path: &Path) -> Result<Vec<u8>> {
        let cache_base = self
            .cache_base_path
            .as_ref()
            .context("could not determine the user cache directory")?;
        let clone_path = cache_base
            .join("com.apple.wallpaper.extension.image")
            .join(uppercase_uuid());
        let mut entry = Dictionary::new();
        entry.insert("id".into(), Value::String(uppercase_uuid()));
        entry.insert(
            "dateAdded".into(),
            Value::Date(plist::Date::from(SystemTime::now())),
        );
        entry.insert(
            "originalURL".into(),
            relative_url_value(file_url(path, true)?),
        );
        entry.insert(
            "originalURLBookmarkData".into(),
            Value::Data(bookmark_data(path, true)?),
        );
        entry.insert(
            "cloneURL".into(),
            relative_url_value(file_url(&clone_path, true)?),
        );
        encode_entry(entry)
    }

    fn create_tahoe_photo_entry(&self, path: &Path) -> Result<Vec<u8>> {
        let cache_base = self
            .cache_base_path
            .as_ref()
            .context("could not determine the user cache directory")?;
        let file_name = path
            .file_name()
            .context("photo path does not contain a file name")?;
        let copy_path = cache_base
            .join("com.apple.wallpaper.extension.image")
            .join(uppercase_uuid())
            .join(file_name);
        let mut entry = Dictionary::new();
        entry.insert(
            "dateAdded".into(),
            Value::Date(plist::Date::from(SystemTime::now())),
        );
        entry.insert(
            "originalURL".into(),
            relative_url_value(file_url(path, false)?),
        );
        entry.insert(
            "originalURLBookmarkData".into(),
            Value::Data(bookmark_data(path, false)?),
        );
        entry.insert(
            "copyURL".into(),
            relative_url_value(file_url(&copy_path, false)?),
        );
        entry.insert(
            "originatingBundleIdentifier".into(),
            Value::String("com.github.virzz.enyo".into()),
        );
        entry.insert("originatingBundleName".into(), Value::String("Enyo".into()));
        encode_entry(entry)
    }

    fn load_tahoe_plist(&self) -> Result<Dictionary> {
        load_dictionary_file(&self.plist_path, true).map(ensure_tahoe_defaults)
    }

    fn save_tahoe_plist(&self, root: &mut Dictionary) -> Result<()> {
        ensure_tahoe_defaults_mut(root)?;
        save_dictionary_file(&self.plist_path, root)
    }
}

fn macos_version() -> Result<String> {
    let output = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .context("failed to run sw_vers")?;
    if !output.status.success() {
        bail!(
            "sw_vers failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let version = String::from_utf8(output.stdout)
        .context("sw_vers returned non-UTF-8 output")?
        .trim()
        .to_string();
    if version.is_empty() {
        bail!("sw_vers returned an empty version")
    }
    Ok(version)
}

fn user_cache_directory() -> Result<PathBuf> {
    let output = Command::new("/usr/bin/getconf")
        .arg("DARWIN_USER_CACHE_DIR")
        .output()
        .context("failed to run getconf DARWIN_USER_CACHE_DIR")?;
    if !output.status.success() {
        bail!(
            "getconf DARWIN_USER_CACHE_DIR failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let path = String::from_utf8(output.stdout)
        .context("getconf returned non-UTF-8 output")?
        .trim()
        .to_string();
    if path.is_empty() {
        bail!("getconf returned an empty user cache directory")
    }
    let path = path
        .strip_prefix("/var/")
        .map(|suffix| PathBuf::from("/private/var").join(suffix))
        .unwrap_or_else(|| PathBuf::from(path));
    Ok(path)
}

fn restart_process(name: &str) -> Result<()> {
    Command::new("/usr/bin/killall")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to restart {name}"))?;
    Ok(())
}

fn copy_preference_dictionary() -> Result<Option<Dictionary>> {
    let key = CFString::new(LEGACY_PREF_PANE);
    let application = CFString::new(LEGACY_DOMAIN);
    // SAFETY: Both strings are live Core Foundation objects. The Copy API returns an owned
    // property-list reference, or null when the preference is absent.
    let value = unsafe {
        CFPreferencesCopyAppValue(key.as_concrete_TypeRef(), application.as_concrete_TypeRef())
    };
    if value.is_null() {
        return Ok(None);
    }

    // SAFETY: CFPreferencesCopyAppValue returned this non-null owned reference.
    let value = unsafe { CFPropertyList::wrap_under_create_rule(value) };
    let data = create_data(
        value.as_concrete_TypeRef(),
        kCFPropertyListBinaryFormat_v1_0,
    )
    .map_err(|error| anyhow!("failed to encode DSKDesktopPrefPane: {error}"))?;
    parse_dictionary(data.bytes(), "DSKDesktopPrefPane").map(Some)
}

fn set_preference_dictionary(pref_pane: &Dictionary) -> Result<()> {
    let mut encoded = Vec::new();
    Value::Dictionary(pref_pane.clone())
        .to_writer_binary(&mut encoded)
        .context("failed to encode DSKDesktopPrefPane")?;
    let (value, _) = create_with_data(CFData::from_buffer(&encoded), kCFPropertyListImmutable)
        .map_err(|error| anyhow!("failed to create DSKDesktopPrefPane property list: {error}"))?;
    // SAFETY: create_with_data returned this non-null owned property-list reference.
    let value = unsafe { CFPropertyList::wrap_under_create_rule(value) };
    let key = CFString::new(LEGACY_PREF_PANE);
    let application = CFString::new(LEGACY_DOMAIN);

    // SAFETY: All Core Foundation references remain live for the duration of both calls.
    let synchronized = unsafe {
        CFPreferencesSetAppValue(
            key.as_concrete_TypeRef(),
            value.as_concrete_TypeRef(),
            application.as_concrete_TypeRef(),
        );
        CFPreferencesAppSynchronize(application.as_concrete_TypeRef())
    };
    if synchronized == 0 {
        bail!("failed to synchronize {LEGACY_DOMAIN} preferences");
    }
    Ok(())
}

fn normalize_path(path: &str) -> Result<PathBuf> {
    let expanded = if path == "~" {
        dirs::home_dir().context("failed to determine the home directory")?
    } else if let Some(suffix) = path.strip_prefix("~/") {
        dirs::home_dir()
            .context("failed to determine the home directory")?
            .join(suffix)
    } else {
        PathBuf::from(path)
    };
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        env::current_dir()
            .context("failed to determine the current directory")?
            .join(expanded)
    };
    Ok(normalize_existing_path(&absolute))
}

fn normalize_existing_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn load_dictionary_file(path: &Path, missing_is_empty: bool) -> Result<Dictionary> {
    match fs::read(path) {
        Ok(data) if data.is_empty() => Ok(Dictionary::new()),
        Ok(data) => parse_dictionary(&data, &format!("plist {}", path.display())),
        Err(error) if missing_is_empty && error.kind() == std::io::ErrorKind::NotFound => {
            Ok(Dictionary::new())
        }
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn save_dictionary_file(path: &Path, root: &Dictionary) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut data = Vec::new();
    Value::Dictionary(root.clone())
        .to_writer_binary(&mut data)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn parse_dictionary(data: &[u8], description: &str) -> Result<Dictionary> {
    Value::from_reader(Cursor::new(data))
        .with_context(|| format!("failed to decode {description}"))?
        .into_dictionary()
        .ok_or_else(|| anyhow!("{description} root is not a dictionary"))
}

fn legacy_folders(root: &Dictionary) -> Result<Vec<PathBuf>> {
    let Some(pref_pane) = root.get(LEGACY_PREF_PANE) else {
        return Ok(Vec::new());
    };
    let pref_pane = pref_pane
        .as_dictionary()
        .context("DSKDesktopPrefPane is not a dictionary")?;
    let Some(folders) = pref_pane.get(LEGACY_FOLDER_PATHS) else {
        return Ok(Vec::new());
    };
    let folders = folders
        .as_array()
        .context("UserFolderPaths is not an array")?;
    folders
        .iter()
        .map(|value| {
            value
                .as_string()
                .map(PathBuf::from)
                .context("UserFolderPaths contains a non-string value")
        })
        .collect()
}

fn set_legacy_folders(root: &mut Dictionary, folders: &[PathBuf]) -> Result<()> {
    if !root.contains_key(LEGACY_PREF_PANE) {
        root.insert(
            LEGACY_PREF_PANE.into(),
            Value::Dictionary(Dictionary::new()),
        );
    }
    let pref_pane = root
        .get_mut(LEGACY_PREF_PANE)
        .and_then(Value::as_dictionary_mut)
        .context("DSKDesktopPrefPane is not a dictionary")?;
    if folders.is_empty() {
        pref_pane.remove(LEGACY_FOLDER_PATHS);
    } else {
        pref_pane.insert(
            LEGACY_FOLDER_PATHS.into(),
            Value::Array(
                folders
                    .iter()
                    .map(|path| Value::String(path.display().to_string()))
                    .collect(),
            ),
        );
    }
    Ok(())
}

fn ensure_tahoe_defaults(mut root: Dictionary) -> Dictionary {
    for key in [ASSETS, COLLECTIONS, IMAGE_FILES, IMAGE_FOLDERS, PEOPLE] {
        if !root.contains_key(key) {
            root.insert(key.into(), Value::Array(Vec::new()));
        }
    }
    for key in MIGRATION_KEYS {
        if !root.contains_key(key) {
            root.insert(key.into(), Value::Boolean(true));
        }
    }
    root
}

fn ensure_tahoe_defaults_mut(root: &mut Dictionary) -> Result<()> {
    for key in [ASSETS, COLLECTIONS, IMAGE_FILES, IMAGE_FOLDERS, PEOPLE] {
        array_mut(root, key)?;
    }
    for key in MIGRATION_KEYS {
        match root.get(key) {
            Some(Value::Boolean(_)) => {}
            Some(_) => bail!("{key} is not a boolean"),
            None => {
                root.insert(key.into(), Value::Boolean(true));
            }
        }
    }
    Ok(())
}

fn array<'a>(root: &'a Dictionary, key: &str) -> Result<Option<&'a [Value]>> {
    root.get(key)
        .map(|value| {
            value
                .as_array()
                .map(Vec::as_slice)
                .with_context(|| format!("{key} is not an array"))
        })
        .transpose()
}

fn array_mut<'a>(root: &'a mut Dictionary, key: &str) -> Result<&'a mut Vec<Value>> {
    if !root.contains_key(key) {
        root.insert(key.into(), Value::Array(Vec::new()));
    }
    root.get_mut(key)
        .and_then(Value::as_array_mut)
        .with_context(|| format!("{key} is not an array"))
}

fn contents(root: &Dictionary) -> Result<YourPhotosContents> {
    Ok(YourPhotosContents {
        image_files: array(root, IMAGE_FILES)?.map_or(0, <[Value]>::len),
        image_folders: array(root, IMAGE_FOLDERS)?.map_or(0, <[Value]>::len),
        assets: array(root, ASSETS)?.map_or(0, <[Value]>::len),
        collections: array(root, COLLECTIONS)?.map_or(0, <[Value]>::len),
        people: array(root, PEOPLE)?.map_or(0, <[Value]>::len),
    })
}

fn entry_paths<'a>(root: &'a Dictionary, key: &str) -> Result<impl Iterator<Item = PathBuf> + 'a> {
    Ok(array(root, key)?
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| entry.as_data())
        .filter_map(|data| parse_dictionary(data, "wallpaper source entry").ok())
        .filter_map(|entry| original_path(&entry).ok()))
}

fn entry_matches_path(entry: &Value, path: &Path) -> bool {
    entry
        .as_data()
        .and_then(|data| parse_dictionary(data, "wallpaper source entry").ok())
        .and_then(|entry| original_path(&entry).ok())
        .is_some_and(|existing| normalize_existing_path(&existing) == path)
}

fn original_path(entry: &Dictionary) -> Result<PathBuf> {
    let original_url = entry
        .get("originalURL")
        .and_then(Value::as_dictionary)
        .and_then(|url| url.get("relative"))
        .and_then(Value::as_string)
        .context("wallpaper entry is missing originalURL.relative")?;
    let url = Url::parse(original_url).context("wallpaper entry has an invalid original URL")?;
    url.to_file_path()
        .map_err(|_| anyhow!("wallpaper entry original URL is not a file URL"))
}

fn relative_url_value(url: Url) -> Value {
    let mut value = Dictionary::new();
    value.insert("relative".into(), Value::String(url.into()));
    Value::Dictionary(value)
}

fn file_url(path: &Path, is_directory: bool) -> Result<Url> {
    if is_directory {
        Url::from_directory_path(path)
    } else {
        Url::from_file_path(path)
    }
    .map_err(|_| anyhow!("could not encode file URL: {}", path.display()))
}

fn encode_entry(entry: Dictionary) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    Value::Dictionary(entry)
        .to_writer_binary(&mut data)
        .context("failed to encode wallpaper source entry")?;
    Ok(data)
}

fn uppercase_uuid() -> String {
    Uuid::new_v4().hyphenated().to_string().to_uppercase()
}

fn bookmark_data(path: &Path, is_directory: bool) -> Result<Vec<u8>> {
    let url = CFURL::from_path(path, is_directory)
        .with_context(|| format!("failed to create file URL for {}", path.display()))?;
    let mut error: CFErrorRef = ptr::null_mut();

    // SAFETY: Every pointer comes from Core Foundation or is null as permitted by the API.
    // The returned create-rule references are immediately wrapped for balanced CFRelease calls.
    let data_ref = unsafe {
        CFURLCreateBookmarkData(
            kCFAllocatorDefault,
            url.as_concrete_TypeRef(),
            kCFURLBookmarkCreationMinimalBookmarkMask,
            ptr::null(),
            ptr::null(),
            &mut error,
        )
    };
    if data_ref.is_null() {
        if error.is_null() {
            bail!("failed to create bookmark data for {}", path.display());
        }
        // SAFETY: CFURLCreateBookmarkData returned this owned CFError reference.
        let error = unsafe { CFError::wrap_under_create_rule(error) };
        bail!(
            "failed to create bookmark data for {}: {error}",
            path.display()
        );
    }
    // SAFETY: A non-null create-rule CFData reference is owned by the caller.
    let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
    Ok(data.bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn manager(mode: StorageMode, plist_path: PathBuf, cache: Option<PathBuf>) -> WallpaperManager {
        WallpaperManager {
            mode,
            os_version: match mode {
                StorageMode::Legacy => "15.0".into(),
                StorageMode::Tahoe => "26.0".into(),
            },
            plist_path,
            cache_base_path: cache,
            use_defaults_domain: false,
        }
    }

    #[test]
    fn legacy_add_list_remove_preserves_other_preferences() {
        let temp = TempDir::new().unwrap();
        let plist_path = temp.path().join("legacy.plist");
        let wallpaper_dir = temp.path().join("wallpapers");
        fs::create_dir(&wallpaper_dir).unwrap();

        let mut pref_pane = Dictionary::new();
        pref_pane.insert("Unrelated".into(), Value::String("preserved".into()));
        let mut root = Dictionary::new();
        root.insert(LEGACY_PREF_PANE.into(), Value::Dictionary(pref_pane));
        save_dictionary_file(&plist_path, &root).unwrap();

        let manager = manager(StorageMode::Legacy, plist_path.clone(), None);
        manager.add_folder(wallpaper_dir.to_str().unwrap()).unwrap();
        assert!(manager
            .is_folder_registered(wallpaper_dir.to_str().unwrap())
            .unwrap());
        assert!(manager.add_folder(wallpaper_dir.to_str().unwrap()).is_err());
        assert_eq!(manager.list_folders().unwrap().len(), 1);

        manager
            .remove_folder(wallpaper_dir.to_str().unwrap())
            .unwrap();
        assert!(manager.list_folders().unwrap().is_empty());
        let saved = load_dictionary_file(&plist_path, false).unwrap();
        assert_eq!(
            saved[LEGACY_PREF_PANE].as_dictionary().unwrap()["Unrelated"].as_string(),
            Some("preserved")
        );
    }

    #[test]
    fn tahoe_manages_folders_and_photos_without_dropping_unknown_keys() {
        let temp = TempDir::new().unwrap();
        let plist_path = temp.path().join("tahoe.plist");
        let cache = temp.path().join("cache");
        let wallpaper_dir = temp.path().join("wallpapers");
        let photo = temp.path().join("photo name.jpg");
        fs::create_dir(&wallpaper_dir).unwrap();
        fs::write(&photo, b"image").unwrap();

        let mut root = ensure_tahoe_defaults(Dictionary::new());
        root.insert("UnknownFutureKey".into(), Value::String("preserved".into()));
        save_dictionary_file(&plist_path, &root).unwrap();

        let manager = manager(StorageMode::Tahoe, plist_path.clone(), Some(cache));
        manager.add_folder(wallpaper_dir.to_str().unwrap()).unwrap();
        manager.add_photo(photo.to_str().unwrap()).unwrap();

        let folders = manager.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].path, wallpaper_dir);
        assert!(folders[0].id.is_some());
        assert!(folders[0].date_added.is_some());
        assert_eq!(manager.list_photos().unwrap()[0].path, photo);
        assert_eq!(
            manager.your_photos_contents().unwrap(),
            YourPhotosContents {
                image_files: 1,
                image_folders: 1,
                ..YourPhotosContents::default()
            }
        );

        let before = manager.reset_your_photos(false).unwrap();
        assert_eq!(before.total(), 2);
        assert!(manager.list_photos().unwrap().is_empty());
        assert_eq!(manager.list_folders().unwrap().len(), 1);

        manager
            .remove_folder(wallpaper_dir.to_str().unwrap())
            .unwrap();
        let saved = load_dictionary_file(&plist_path, false).unwrap();
        assert_eq!(saved["UnknownFutureKey"].as_string(), Some("preserved"));
    }

    #[test]
    fn tahoe_entry_keys_match_macos_required_order() {
        let temp = TempDir::new().unwrap();
        let wallpaper_dir = temp.path().join("wallpapers");
        fs::create_dir(&wallpaper_dir).unwrap();
        let manager = manager(
            StorageMode::Tahoe,
            temp.path().join("tahoe.plist"),
            Some(temp.path().join("cache")),
        );

        let data = manager.create_tahoe_folder_entry(&wallpaper_dir).unwrap();
        let entry = parse_dictionary(&data, "test entry").unwrap();
        assert_eq!(
            entry.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "id",
                "dateAdded",
                "originalURL",
                "originalURLBookmarkData",
                "cloneURL",
            ]
        );
    }
}
