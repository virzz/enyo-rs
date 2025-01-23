use anyhow::{anyhow, Result};
use clap::Parser;
use std::{fs, path::Path};

#[derive(Parser)]
#[command(name = "sitemap")]
pub struct Args {
    #[arg(short = 'i', long = "input", help = "URLS input")]
    input: Vec<String>,

    #[arg(short = 'o', long = "output", help = "Message Subject")]
    output: Option<String>,
}

use sitemap::structs::UrlEntry;
use sitemap::writer::SiteMapWriter;

pub fn execute(args: &Args) -> Result<()> {
    let mut items = Vec::new();
    let input = args.input.clone();
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
    let output = args.output.clone().unwrap_or("sitemap.xml".to_string());
    fs::write(output.clone(), buf)?;
    println!("Sitemap generated at {}", output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_none() {
        let _ = execute(&Args {
            input: vec!["http://aaa.com".to_string()],
            output: None,
        });
    }
}
