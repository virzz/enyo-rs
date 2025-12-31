use anyhow::Result;
use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};
use tracing::debug;

pub type IoData = Vec<u8>;
pub type Inputs = Vec<IoData>;
pub type Outputs = Vec<IoData>;

pub fn input(args: &Option<Vec<String>>) -> Result<IoData> {
    match &args {
        Some(input) if !input.is_empty() && !input[0].is_empty() => {
            let path = PathBuf::from(input[0].clone());
            if path.exists() {
                if let std::result::Result::Ok(buf) = fs::read(path) {
                    debug!("Input from file");
                    return Ok(buf);
                }
            }
            debug!("Input from data");
            Ok(input[0].as_bytes().to_vec())
        }
        _ => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            debug!("Input from stdin");
            Ok(buffer)
        }
    }
}

pub fn inputs(args: Option<Vec<String>>) -> Result<Inputs> {
    let mut results: Inputs = Vec::new();
    match &args {
        Some(inputs) => {
            inputs.iter().for_each(|input| {
                let path = PathBuf::from(input.clone());
                if path.exists() {
                    if let std::result::Result::Ok(buf) = fs::read(path) {
                        debug!("Input from file");
                        results.push(buf);
                    }
                }
                results.push(input.as_bytes().to_vec());
            });
        }
        _ => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            debug!("Input from stdin");
            results.push(buffer);
        }
    }
    Ok(results)
}

pub fn output(result: &IoData, is_bin: bool) -> Result<()> {
    if is_bin {
        io::stdout().write_all(result)?;
    } else {
        println!("{}", String::from_utf8_lossy(result));
    }
    Ok(())
}

pub fn outputs(results: &Outputs, is_bin: bool) -> Result<()> {
    for result in results {
        output(result, is_bin)?;
    }
    Ok(())
}
