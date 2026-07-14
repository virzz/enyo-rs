pub trait Action: Send + Sync {
    fn execute(&self) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}
