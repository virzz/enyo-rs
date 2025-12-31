# SubCmd

自动添加到 `./mod.rs` 的 `enum Command`和`invoke match`中

## struct

```rs
#[derive(Parser)]
#[command(name = "cmd_name")]
pub struct Cmd {

    // flag 参数
    #[arg(short = 'f', help = "Print format")]
    {arg}: Option<String>,

    // args 参数
    #[arg(help = "Any args")]
    args: Option<Vec<String>>,
}
```

## impl CmdExecute::execute

```rs
impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        match self.args.clone() {
            None => println!("{}", Local::now().timestamp()),
            Some(ts) => {
                let result = "";
                // TODO sth
                // result = ...
                println!("{}",result);
            }
        }
        Ok(())
    }
}
```

## tests

需要对`execute`生成合适的测试

```rs

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_none() {
        let _ = Cmd {
            format: None,
            time: None,
        }
        .execute()
        .await;
    }
}
```