//! @alias: sm
//! @about: Generate sitemap.xml with given URLs

use anyhow::{anyhow, Result};
use clap::Parser;
use sitemap::{structs::UrlEntry, writer::SiteMapWriter};
use std::{fs, path::Path};

use crate::Action;

#[derive(Parser)]
#[command(name = "sitemap")]
pub struct Cmd {
    #[arg(short = 'i', long = "input", help = "URLS input")]
    input: Vec<String>,

    #[arg(short = 'o', long = "output", help = "Message Subject")]
    output: Option<String>,
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        let mut items = Vec::new();
        let input = self.input.clone();
        if input.len() == 1 {
            let input = input.first().ok_or(anyhow!("No input"))?;
            if Path::new(input).is_file() {
                fs::read_to_string(input)?.split("\n").for_each(|lines| {
                    lines.split(",").for_each(|line| {
                        items.push(line.to_string());
                    });
                });
            } else {
                items.push(input.to_string());
            }
        } else {
            input.iter().for_each(|url| {
                items.push(url.to_string());
            });
        }
        let mut buf = Vec::<u8>::new();
        let sitemap_writer = SiteMapWriter::new(&mut buf);
        let mut urlwriter = sitemap_writer.start_urlset()?;
        items.iter().for_each(|url| {
            let _ = urlwriter.url(UrlEntry::builder().loc(url));
        });
        urlwriter.end()?;
        match &self.output {
            Some(output) => {
                fs::write(output, buf)?;
                println!("Sitemap generated at {output}");
            }
            None => {
                println!("Sitemap generated\n{}", String::from_utf8_lossy(&buf));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_none() {
        let _ = Cmd {
            input: vec!["http://aaa.com".to_string()],
            output: None,
        }
        .execute()
        .await;
    }
}
