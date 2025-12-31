use anyhow::{Ok, Result};
use clap::{CommandFactory, Parser};
use clap_complete::aot::{generate, Shell};
use std::{io, path::PathBuf};

use crate::{App, CmdExecute};

#[derive(Parser)]
#[command(name = "comp")]
pub struct Cmd {
    #[arg(short, long, help = "generate completion file")]
    file: Option<PathBuf>,

    #[arg(help = "shell type")]
    shell: Option<Vec<Shell>>,
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        let mut cmd = App::command();
        let bin_name = cmd
            .get_bin_name()
            .unwrap_or(env!("CARGO_PKG_NAME"))
            .to_string();
        self.shell
            .clone()
            .unwrap_or(vec![Shell::Bash])
            .iter()
            .for_each(|&shell| {
                generate(shell, &mut cmd, &bin_name, &mut io::stdout());
            });
        Ok(())
    }
}
