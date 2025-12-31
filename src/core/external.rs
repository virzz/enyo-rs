use anyhow::Result;
use std::process::Command;

/// 执行外部命令
pub fn external(args: &[String]) -> Result<()> {
    let mut cmd = Command::new(args[0].clone());
    if args.len() > 1 {
        cmd.args(args[1..].iter());
    }
    let output = cmd.output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}
