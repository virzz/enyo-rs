use anyhow::Result;
use std::future::Future;

pub trait CmdExecute {
    fn execute(&self) -> impl Future<Output = Result<()>> + Send;
}

pub mod completion;
pub mod external;
pub mod io;

pub use completion::Cmd;
pub use external::external;
pub use io::{input, inputs, output, outputs, Inputs, IoData, Outputs};
