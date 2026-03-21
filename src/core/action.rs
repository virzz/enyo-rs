#[async_trait::async_trait]
pub trait Action: Send + Sync {
    async fn execute(&self) -> anyhow::Result<()>;
}
