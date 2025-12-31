//! @about: Parse various file formats (DS_Store, /proc/net)

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

mod ds_store;
mod proc_net;

use crate::CmdExecute;

#[derive(Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    command: SubCmd,
}

#[derive(Subcommand)]
pub enum SubCmd {
    /// Parse /proc/net/tcp|udp
    #[clap(alias = "net")]
    Procnet {
        /// File path to parse
        #[arg(short = 'f', long)]
        filepath: Option<String>,

        /// Input data
        input: Option<String>,
    },

    /// .DS_Store Parser
    Dsstore {
        /// Target file path or URL
        target: String,
    },
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        match &self.command {
            SubCmd::Procnet { filepath, input } => {
                let path = filepath.as_ref().or(input.as_ref())
                    .ok_or_else(|| anyhow!("Invalid filepath"))?;
                let result = proc_net::parse_proc_net(path)?;
                println!("{result}");
            }
            SubCmd::Dsstore { target } => {
                let result = ds_store::parse_ds_store(target).await?;
                println!("{result}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    

    #[tokio::test]
    async fn test_procnet() {
        // 需要实际的测试文件
        // let cmd = Cmd {
        //     command: SubCmd::Procnet {
        //         filepath: Some("tests/proc_net_tcp".to_string()),
        //         input: None,
        //     },
        // };
        // cmd.execute().await.unwrap();
    }
}

