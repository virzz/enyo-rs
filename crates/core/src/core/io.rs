use anyhow::Result;
use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};
use tracing::debug;

/// 输入来源
#[derive(Debug, Clone)]
pub enum InputSource {
    /// 从标准输入读取
    Stdin,
    /// 从文件读取
    File(PathBuf),
    /// 从命令行参数直接传入
    Arg,
}

/// 输出目标
#[derive(Debug, Clone)]
pub enum OutputTarget {
    /// 输出到标准输出
    Stdout,
    /// 输出到文件
    File(PathBuf),
}

/// 携带来源信息的输入数据
#[derive(Debug, Clone)]
pub struct Input {
    pub data: Vec<u8>,
    pub source: InputSource,
}

impl Input {
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.data).trim().to_string()
    }
}

impl std::ops::Deref for Input {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl AsRef<[u8]> for Input {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

pub fn input(args: &Option<Vec<String>>) -> Result<Input> {
    match &args {
        Some(input) if !input.is_empty() && !input[0].is_empty() => {
            let path = PathBuf::from(input[0].clone());
            if path.exists() {
                if let std::result::Result::Ok(buf) = fs::read(&path) {
                    debug!("Input from file: {}", path.display());
                    return Ok(Input {
                        data: buf,
                        source: InputSource::File(path),
                    });
                }
            }
            debug!("Input from arg");
            Ok(Input {
                data: input[0].as_bytes().to_vec(),
                source: InputSource::Arg,
            })
        }
        _ => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            debug!("Input from stdin");
            Ok(Input {
                data: buffer,
                source: InputSource::Stdin,
            })
        }
    }
}

pub fn inputs(args: Option<Vec<String>>) -> Result<Vec<Input>> {
    let mut results: Vec<Input> = Vec::new();
    match &args {
        Some(inputs) => {
            for item in inputs.iter() {
                let path = PathBuf::from(item.clone());
                if path.exists() {
                    if let std::result::Result::Ok(buf) = fs::read(&path) {
                        debug!("Input from file: {}", path.display());
                        results.push(Input {
                            data: buf,
                            source: InputSource::File(path),
                        });
                        continue;
                    }
                }
                results.push(Input {
                    data: item.as_bytes().to_vec(),
                    source: InputSource::Arg,
                });
            }
        }
        _ => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            debug!("Input from stdin");
            results.push(Input {
                data: buffer,
                source: InputSource::Stdin,
            });
        }
    }
    Ok(results)
}

pub fn output(data: &[u8], target: &OutputTarget, binary: bool) -> Result<()> {
    match target {
        OutputTarget::Stdout => {
            if binary {
                io::stdout().write_all(data)?;
            } else {
                println!("{}", String::from_utf8_lossy(data));
            }
        }
        OutputTarget::File(path) => {
            anyhow::ensure!(
                !path.exists(),
                "Output file already exists: {}",
                path.display()
            );
            fs::write(path, data)?;
            debug!("Output to file: {}", path.display());
        }
    }
    Ok(())
}

/// 向后兼容的便捷方法：输出到 stdout
pub fn print(data: &[u8], binary: bool) -> Result<()> {
    output(data, &OutputTarget::Stdout, binary)
}
