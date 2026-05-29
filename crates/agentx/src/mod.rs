//! @alias: ax
//! @about: Download and manage agent skills

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use chrono::{Local, SecondsFormat};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use enyo_core::Action;

const CACHE_DIR: &str = ".cache/enyo";
const STORAGE_DIR: &str = ".agents/skills";
const INDEX_FILE: &str = ".enyo.skills.json";

/// SKILL.md YAML frontmatter metadata
#[derive(Debug, Deserialize)]
struct SkillMeta {
    name: String,
    description: Option<String>,
}

/// Index entry for an installed skill
#[derive(Debug, Serialize, Deserialize)]
struct SkillIndex {
    name: String,
    repo: String,
    commit_hash: String,
    updated_at: String,
}

const DEFAULT_REGISTRY: &str = "github.com";

/// Parsed repository reference: {registry}/[subgroup/]{owner}/{repo}
#[derive(Debug, Clone)]
struct RepoRef {
    registry: String,
    path: String,
}

impl RepoRef {
    /// Parse a repo string into a RepoRef.
    ///
    /// - `owner/repo` => registry=github.com, path=owner/repo
    /// - `github.com/owner/repo` => registry=github.com, path=owner/repo
    /// - `git.example.com/group/owner/repo` => registry=git.example.com, path=group/owner/repo
    fn parse(input: &str) -> Result<Self> {
        // Strip protocol prefix if present
        let input = input
            .strip_prefix("https://")
            .or_else(|| input.strip_prefix("http://"))
            .unwrap_or(input);
        // Strip trailing .git and /
        let input = input
            .strip_suffix(".git")
            .unwrap_or(input)
            .trim_end_matches('/');

        let parts: Vec<&str> = input.splitn(3, '/').collect();
        match parts.len() {
            // owner/repo => shorthand
            2 => Ok(Self {
                registry: DEFAULT_REGISTRY.to_string(),
                path: format!("{}/{}", parts[0], parts[1]),
            }),
            // registry/...path (3+ segments)
            3 => {
                let first = parts[0];
                if first.contains('.') {
                    // Looks like a domain: registry/remaining_path
                    Ok(Self {
                        registry: first.to_string(),
                        path: format!("{}/{}", parts[1], parts[2]),
                    })
                } else {
                    // No dot in first segment, treat as shorthand with subgroup
                    Ok(Self {
                        registry: DEFAULT_REGISTRY.to_string(),
                        path: format!("{}/{}/{}", parts[0], parts[1], parts[2]),
                    })
                }
            }
            _ => bail!(
                "Invalid repo format: '{}'. Expected [registry/][subgroup/]owner/repo",
                input
            ),
        }
    }

    /// Git clone URL
    fn url(&self) -> String {
        format!("https://{}/{}.git", self.registry, self.path)
    }

    /// Local cache directory path: {cache_dir}/{registry}/{path}
    fn cache_path(&self, cache: &Path) -> PathBuf {
        cache.join(&self.registry).join(&self.path)
    }
}

/// Download and manage agent skills
#[derive(Debug, Parser)]
#[clap(name = "agentx")]
pub struct Cmd {
    /// Git repository (e.g. owner/repo, github.com/owner/repo)
    #[arg()]
    repo: String,

    /// Install specific skill by name
    #[arg(short = 's', long = "skill")]
    skill: Option<String>,
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().context("Failed to determine home directory")
}

fn cache_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(CACHE_DIR))
}

fn storage_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(STORAGE_DIR))
}

/// Run a git command in the given directory
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    debug!("git {}", args.join(" "));
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .context("Failed to execute git")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args[0], stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Initialize a sparse checkout clone of the repo
fn sparse_clone(repo: &RepoRef, repo_dir: &Path) -> Result<()> {
    let repo_url = repo.url();
    info!("Cloning {} (sparse) ...", repo_url);
    fs::create_dir_all(repo_dir)?;

    git(repo_dir, &["init"])?;
    git(repo_dir, &["remote", "add", "origin", &repo_url])?;
    git(repo_dir, &["sparse-checkout", "init", "--cone"])?;
    // Set empty pattern to only checkout root-level files
    git(repo_dir, &["sparse-checkout", "set"])?;
    git(
        repo_dir,
        &[
            "fetch",
            "--depth",
            "1",
            "--filter=blob:none",
            "origin",
            "HEAD",
        ],
    )?;
    git(repo_dir, &["checkout", "FETCH_HEAD"])?;
    Ok(())
}

/// Update an existing sparse checkout repo
fn sparse_update(repo_dir: &Path) -> Result<()> {
    info!("Updating sparse checkout ...");
    git(repo_dir, &["fetch", "--depth", "1", "origin", "HEAD"])?;
    git(repo_dir, &["checkout", "FETCH_HEAD"])?;
    Ok(())
}

/// Skill entry: leaf name + full relative path from repo root
struct SkillEntry {
    name: String,
    rel_path: PathBuf,
}

/// Use `git ls-tree` to find all SKILL.md files and their parent directories
fn find_skills(repo_dir: &Path) -> Result<Vec<SkillEntry>> {
    let output = git(repo_dir, &["ls-tree", "-r", "--name-only", "HEAD"])?;
    let skills: Vec<SkillEntry> = output
        .lines()
        .filter(|line| line.ends_with("/SKILL.md"))
        .filter_map(|line| {
            let path = Path::new(line);
            let parent = path.parent()?;
            let name = parent.file_name()?.to_string_lossy().to_string();
            Some(SkillEntry {
                name,
                rel_path: parent.to_path_buf(),
            })
        })
        .collect();
    Ok(skills)
}

/// Checkout specific directories via sparse-checkout
fn checkout_dirs(repo_dir: &Path, dirs: &[&str]) -> Result<()> {
    if dirs.is_empty() {
        return Ok(());
    }
    let mut args = vec!["sparse-checkout", "add"];
    args.extend(dirs);
    git(repo_dir, &args)?;
    Ok(())
}

/// Parse SKILL.md YAML frontmatter
fn parse_skill_md(path: &Path) -> Result<SkillMeta> {
    let content = fs::read_to_string(path).context("Failed to read SKILL.md")?;
    let content = content.trim();
    if !content.starts_with("---") {
        bail!("SKILL.md missing YAML frontmatter");
    }
    let rest = &content[3..];
    let end = rest
        .find("---")
        .context("SKILL.md missing closing frontmatter delimiter")?;
    let yaml = &rest[..end];
    let meta: SkillMeta = serde_yaml::from_str(yaml).context("Failed to parse SKILL.md YAML")?;
    Ok(meta)
}

/// Get current HEAD commit hash
fn get_commit_hash(repo_dir: &Path) -> Result<String> {
    git(repo_dir, &["rev-parse", "HEAD"])
}

/// Read the index file
fn read_index(storage: &Path) -> Result<HashMap<String, SkillIndex>> {
    let index_path = storage.join(INDEX_FILE);
    if !index_path.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(&index_path)?;
    let index: HashMap<String, SkillIndex> = serde_json::from_str(&content)?;
    Ok(index)
}

/// Write the index file
fn write_index(storage: &Path, index: &HashMap<String, SkillIndex>) -> Result<()> {
    let index_path = storage.join(INDEX_FILE);
    let content = serde_json::to_string_pretty(index)?;
    fs::write(&index_path, content)?;
    Ok(())
}

/// Prompt the user for yes/no confirmation
fn confirm(prompt: &str) -> bool {
    eprint!("{} [y/N] ", prompt);
    io::stderr().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Copy a skill directory to storage, handling conflicts
fn install_skill(
    repo_dir: &Path,
    skill_rel_path: &Path,
    skill_name: &str,
    storage: &Path,
    repo_url: &str,
) -> Result<SkillMeta> {
    let src = repo_dir.join(skill_rel_path);
    let dest = storage.join(skill_name);
    let meta = parse_skill_md(&src.join("SKILL.md"))?;
    let commit_hash = get_commit_hash(repo_dir)?;

    // Check if skill already exists in storage
    if dest.exists() {
        let index = read_index(storage)?;
        if let Some(existing) = index.get(skill_name) {
            // Indexed skill: auto-update if commit changed
            if existing.commit_hash == commit_hash {
                info!("Skill '{}' is already up to date", skill_name);
                return Ok(meta);
            }
            info!(
                "Updating skill '{}' ({} -> {})",
                skill_name,
                &existing.commit_hash[..8.min(existing.commit_hash.len())],
                &commit_hash[..8.min(commit_hash.len())]
            );
        } else {
            // Not in index: ask user before overwriting
            if !confirm(&format!(
                "Skill '{}' exists but is not indexed. Overwrite?",
                skill_name
            )) {
                bail!("Aborted by user");
            }
        }
        fs::remove_dir_all(&dest)?;
    }

    copy_dir_recursive(&src, &dest)?;

    // Update index
    let mut index = read_index(storage)?;
    index.insert(
        skill_name.to_string(),
        SkillIndex {
            name: meta.name.clone(),
            repo: repo_url.to_string(),
            commit_hash,
            updated_at: Local::now().to_rfc3339_opts(SecondsFormat::Secs, false),
        },
    );
    write_index(storage, &index)?;

    Ok(meta)
}

/// Recursively copy a directory
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dest.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        let repo_ref = RepoRef::parse(&self.repo)?;
        let cache = cache_dir()?;
        let storage = storage_dir()?;
        fs::create_dir_all(&storage)?;

        let repo_dir = repo_ref.cache_path(&cache);
        let is_new = !repo_dir.exists();

        // Clone or update repo
        if is_new {
            sparse_clone(&repo_ref, &repo_dir)?;
        } else {
            sparse_update(&repo_dir)?;
        }

        // Discover all skill directories
        let skills = find_skills(&repo_dir)?;
        if skills.is_empty() {
            warn!("No skills found in repository");
            return Ok(());
        }

        // Checkout all skill directories (using full relative paths)
        let dirs: Vec<&str> = skills
            .iter()
            .map(|s| s.rel_path.to_str().unwrap_or(""))
            .collect();
        checkout_dirs(&repo_dir, &dirs)?;

        if let Some(ref target) = self.skill {
            // Install specific skill
            let entry = skills
                .iter()
                .find(|s| s.name == *target)
                .with_context(|| format!("Skill '{}' not found in repository", target))?;
            let repo_url = repo_ref.url();
            let meta = install_skill(&repo_dir, &entry.rel_path, &entry.name, &storage, &repo_url)?;
            println!("Installed skill '\x1b[1;33m{}\x1b[0m'", meta.name,);
        } else {
            // List all skills
            for entry in &skills {
                let skill_md = repo_dir.join(&entry.rel_path).join("SKILL.md");
                match parse_skill_md(&skill_md) {
                    Ok(meta) => {
                        // name: bold yellow, description: gray with tab indent
                        println!("\x1b[1;33m{}\x1b[0m", meta.name);
                        if let Some(desc) = &meta.description {
                            println!("\t\x1b[90m{}\x1b[0m", desc);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse {}/SKILL.md: {}", entry.name, e);
                        println!("\x1b[1;33m{}\x1b[0m", entry.name);
                        println!("\t\x1b[90m(unable to parse metadata)\x1b[0m");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_parse_skill_md() {
        let dir = TempDir::new().unwrap();
        let skill_md = dir.path().join("SKILL.md");
        let mut f = fs::File::create(&skill_md).unwrap();
        writeln!(
            f,
            "---\nname: test-skill\ndescription: A test skill\n---\n# Test"
        )
        .unwrap();

        let meta = parse_skill_md(&skill_md).unwrap();
        assert_eq!(meta.name, "test-skill");
        assert_eq!(meta.description.as_deref(), Some("A test skill"));
    }

    #[test]
    fn test_parse_skill_md_no_frontmatter() {
        let dir = TempDir::new().unwrap();
        let skill_md = dir.path().join("SKILL.md");
        fs::write(&skill_md, "# No frontmatter").unwrap();

        assert!(parse_skill_md(&skill_md).is_err());
    }

    #[test]
    fn test_copy_dir_recursive() {
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();

        fs::write(src.path().join("a.txt"), "hello").unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/b.txt"), "world").unwrap();

        let dest_path = dest.path().join("copy");
        copy_dir_recursive(src.path(), &dest_path).unwrap();

        assert_eq!(
            fs::read_to_string(dest_path.join("a.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            fs::read_to_string(dest_path.join("sub/b.txt")).unwrap(),
            "world"
        );
    }

    #[test]
    fn test_index_read_write() {
        let dir = TempDir::new().unwrap();
        let mut index = HashMap::new();
        index.insert(
            "test-skill".to_string(),
            SkillIndex {
                name: "test-skill".to_string(),
                repo: "https://github.com/xxx/yyy.git".to_string(),
                commit_hash: "abc123".to_string(),
                updated_at: "2026-01-01T00:00:00+08:00".to_string(),
            },
        );

        write_index(dir.path(), &index).unwrap();
        let loaded = read_index(dir.path()).unwrap();

        assert_eq!(loaded["test-skill"].name, "test-skill");
        assert_eq!(loaded["test-skill"].commit_hash, "abc123");
    }

    #[test]
    fn test_repo_ref_shorthand() {
        let r = RepoRef::parse("xxx/yyy").unwrap();
        assert_eq!(r.registry, "github.com");
        assert_eq!(r.path, "xxx/yyy");
        assert_eq!(r.url(), "https://github.com/xxx/yyy.git");
    }

    #[test]
    fn test_repo_ref_full_github() {
        let r = RepoRef::parse("github.com/xxx/yyy").unwrap();
        assert_eq!(r.registry, "github.com");
        assert_eq!(r.path, "xxx/yyy");
    }

    #[test]
    fn test_repo_ref_custom_registry_with_subgroup() {
        let r = RepoRef::parse("git.text.com/aaa/xxx/yyy").unwrap();
        assert_eq!(r.registry, "git.text.com");
        assert_eq!(r.path, "aaa/xxx/yyy");
        assert_eq!(r.url(), "https://git.text.com/aaa/xxx/yyy.git");
    }

    #[test]
    fn test_repo_ref_with_protocol() {
        let r = RepoRef::parse("https://github.com/xxx/yyy.git").unwrap();
        assert_eq!(r.registry, "github.com");
        assert_eq!(r.path, "xxx/yyy");
    }

    #[test]
    fn test_repo_ref_cache_path() {
        let r = RepoRef::parse("git.text.com/aaa/xxx/yyy").unwrap();
        let cache = Path::new("/tmp/cache");
        assert_eq!(
            r.cache_path(cache),
            Path::new("/tmp/cache/git.text.com/aaa/xxx/yyy")
        );
    }

    #[test]
    fn test_repo_ref_invalid() {
        assert!(RepoRef::parse("single").is_err());
    }
}
