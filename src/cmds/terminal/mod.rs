//! @alias: term
//! @about: Terminal environment helpers

use std::{collections::HashSet, env, process::Command as ProcessCommand};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};

use crate::Action;

#[derive(Parser)]
#[command(name = "terminal")]
pub struct Cmd {
    #[command(subcommand)]
    command: Option<SubCmd>,
}

#[derive(Subcommand)]
enum SubCmd {
    /// Deduplicate PATH entries, keeping the first occurrence
    #[clap(alias = "uniq_path", alias = "uniq")]
    UniqPath {
        /// PATH string to process. Defaults to current PATH.
        path: Option<String>,
    },

    /// Copy an ssh-agent public key to a remote authorized_keys file
    #[clap(alias = "copy-id", alias = "ssh-copy-id")]
    SshCopyId {
        /// Case-insensitive keyword used to select a key from ssh-add -L.
        name: Option<String>,

        /// Remote ssh host.
        host: Option<String>,
    },
}

fn uniq_path(path: &str) -> String {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();

    for item in path.split(':') {
        if seen.insert(item) {
            paths.push(item);
        }
    }

    paths.join(":")
}

fn find_ssh_key<'a>(keys: &'a str, name: &str) -> Option<&'a str> {
    let needle = name.to_lowercase();

    keys.lines()
        .find(|line| line.to_lowercase().contains(&needle))
}

fn matching_ssh_keys(keys: &str, name: &str) -> String {
    let needle = name.to_lowercase();

    keys.lines()
        .filter(|line| line.to_lowercase().contains(&needle))
        .collect::<Vec<_>>()
        .join("\n")
}

fn ssh_key_blob(key: &str) -> Result<&str> {
    key.split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("Invalid ssh public key"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn build_authorized_keys_script(key: &str) -> String {
    let skey = shell_quote(ssh_key_blob(key).unwrap_or_default());
    let key = shell_quote(key);

    format!(
        "mkdir -p ~/.ssh;chmod 755 ~/.ssh;[ -f ~/.ssh/authorized_keys ] || touch ~/.ssh/authorized_keys;grep -q {skey} ~/.ssh/authorized_keys || printf '\\n%s\\n' {key} >> ~/.ssh/authorized_keys;chmod 600 ~/.ssh/authorized_keys;"
    )
}

fn ssh_add_list() -> Result<String> {
    let output = ProcessCommand::new("ssh-add").arg("-L").output()?;

    if !output.status.success() {
        return Err(anyhow!(
            "ssh-add -L failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn copy_ssh_key(name: &str, host: &str, keys: &str) -> Result<()> {
    let Some(key) = find_ssh_key(keys, name) else {
        println!("Not found key: {name}");
        return Ok(());
    };

    let script = general_purpose::STANDARD.encode(build_authorized_keys_script(key));
    let remote_script = format!("echo {script} | base64 -d | sh");

    println!("ssh {host} '{remote_script}'");

    let status = ProcessCommand::new("ssh")
        .args([
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            host,
            &remote_script,
        ])
        .status()?;

    if !status.success() {
        return Err(anyhow!("ssh-copy-id command failed"));
    }

    let whoami = ProcessCommand::new("ssh").args([host, "whoami"]).output()?;
    if !whoami.status.success() {
        return Err(anyhow!(
            "ssh whoami failed: {}",
            String::from_utf8_lossy(&whoami.stderr).trim()
        ));
    }

    println!(
        "Copied and User: {}",
        String::from_utf8_lossy(&whoami.stdout).trim()
    );

    Ok(())
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        match &self.command {
            Some(SubCmd::SshCopyId { name, host }) => {
                let keys = ssh_add_list()?;
                match (name, host) {
                    (None, _) => println!("{keys}"),
                    (Some(name), None) => println!("{}", matching_ssh_keys(&keys, name)),
                    (Some(name), Some(host)) => copy_ssh_key(name, host, &keys)?,
                }
            }
            Some(SubCmd::UniqPath { path }) => {
                let path = path
                    .clone()
                    .unwrap_or_else(|| env::var("PATH").unwrap_or_default());

                println!("{}", uniq_path(&path));
            }
            None => {
                let path = env::var("PATH").unwrap_or_default();

                println!("{}", uniq_path(&path));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniq_path_keeps_first_occurrence_order() {
        let input = "/usr/bin:/bin:/usr/bin:/opt/bin:/bin";

        assert_eq!(uniq_path(input), "/usr/bin:/bin:/opt/bin");
    }

    #[test]
    fn uniq_path_deduplicates_empty_segments() {
        let input = "/usr/bin::/bin::/usr/bin:";

        assert_eq!(uniq_path(input), "/usr/bin::/bin");
    }

    #[test]
    fn find_ssh_key_filters_case_insensitively() {
        let keys = concat!(
            "ssh-ed25519 AAAA1111 Work-Mac\n",
            "ssh-rsa BBBB2222 prod-server\n"
        );

        assert_eq!(
            find_ssh_key(keys, "work").unwrap(),
            "ssh-ed25519 AAAA1111 Work-Mac"
        );
    }

    #[test]
    fn build_authorized_keys_script_appends_missing_key() {
        let key = "ssh-ed25519 AAAA1111 Work-Mac";

        assert_eq!(
            build_authorized_keys_script(key),
            "mkdir -p ~/.ssh;chmod 755 ~/.ssh;[ -f ~/.ssh/authorized_keys ] || touch ~/.ssh/authorized_keys;grep -q 'AAAA1111' ~/.ssh/authorized_keys || printf '\\n%s\\n' 'ssh-ed25519 AAAA1111 Work-Mac' >> ~/.ssh/authorized_keys;chmod 600 ~/.ssh/authorized_keys;"
        );
    }
}
