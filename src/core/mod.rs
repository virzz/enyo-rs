pub mod action;
pub mod external;
pub mod io;

pub use action::Action;
pub use external::external;
pub use io::{input, inputs, output, print, Input, InputSource, OutputTarget};

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use clap::Parser;

    use super::*;

    // 测试用的 Action
    #[derive(Debug, Clone, Parser)]
    #[command(about, long_about = None)]
    struct TestAction {
        #[arg(short = 'i', long, default_value = "test")]
        pub input: String,
    }

    #[async_trait::async_trait]
    impl Action for TestAction {
        async fn execute(&self) -> Result<()> {
            println!("TestAction execute with input: {}", self.input);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_action_execute() {
        let action = TestAction {
            input: "test".to_string(),
        };
        let result = action.execute().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_action_command() {
        let args = vec!["enyo", "test", "-i", "test"];
        let action_cmd = TestAction::parse_from(args);
        let result = action_cmd.execute().await;
        assert!(result.is_ok());
    }
}
