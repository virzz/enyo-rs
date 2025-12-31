//! @alias: pow
//! @about: Hash Power of Work brute force (MD5/SHA1)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};

use md5::{Digest, Md5};
use rayon::prelude::*;
use sha1::Sha1;

use crate::CmdExecute;

#[derive(Clone, ValueEnum)]
pub enum HashMethod {
    Md5,
    Sha1,
}

#[derive(Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cmd {
    /// Request code (the hash prefix/suffix to match)
    #[arg(short = 'c', long, required = true)]
    code: String,

    /// Starting position of hash to match
    #[arg(short = 'i', long, default_value = "0")]
    pos: usize,

    /// Prefix for hash input
    #[arg(short = 'p', long, default_value = "")]
    prefix: String,

    /// Suffix for hash input
    #[arg(short = 's', long, default_value = "")]
    suffix: String,

    /// Hash method: md5 or sha1
    #[arg(short = 'm', long, default_value = "md5")]
    method: HashMethod,
}

/// 生成随机字节
fn random_bytes(len: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..len).map(|_| rng.random::<u8>()).collect()
}

/// 计算哈希值
fn compute_hash(data: &[u8], method: &HashMethod) -> String {
    match method {
        HashMethod::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashMethod::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
    }
}

/// Hash PoW 暴力破解
fn hash_pow(
    code: &str,
    prefix: &str,
    suffix: &str,
    method: &HashMethod,
    start_pos: usize,
) -> Result<String> {
    let found = Arc::new(AtomicBool::new(false));
    let code_len = code.len();
    let end_pos = start_pos + code_len;

    // 验证位置参数
    let max_len = match method {
        HashMethod::Md5 => 32,
        HashMethod::Sha1 => 40,
    };

    if end_pos > max_len {
        return Err(anyhow!("Invalid position: code would exceed hash length"));
    }

    // 并行搜索
    let result: Option<(String, String)> = (0..u64::MAX).into_par_iter().find_map_any(|_| {
        if found.load(Ordering::Relaxed) {
            return None;
        }

        let random = random_bytes(8);
        let random_str = hex::encode(&random);

        let mut input = String::new();
        if !prefix.is_empty() {
            input.push_str(prefix);
        }
        input.push_str(&random_str);
        if !suffix.is_empty() {
            input.push_str(suffix);
        }

        let hash = compute_hash(input.as_bytes(), method);

        if &hash[start_pos..end_pos] == code {
            found.store(true, Ordering::Relaxed);
            return Some((input.clone(), hash));
        }

        None
    });

    match result {
        Some((input, hash)) => {
            println!(
                "method: {:?} hash = {} result = {}",
                match method {
                    HashMethod::Md5 => "md5",
                    HashMethod::Sha1 => "sha1",
                },
                hash,
                input
            );
            Ok(input)
        }
        None => Err(anyhow!("No result found")),
    }
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        let result = hash_pow(
            &self.code,
            &self.prefix,
            &self.suffix,
            &self.method,
            self.pos,
        )?;
        println!("{result}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_md5() {
        let hash = compute_hash(b"test", &HashMethod::Md5);
        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_compute_hash_sha1() {
        let hash = compute_hash(b"test", &HashMethod::Sha1);
        assert_eq!(hash, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
    }

    #[test]
    fn test_hash_pow_short() {
        // 测试简短的匹配
        let result = hash_pow("00", "test", "", &HashMethod::Md5, 0);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hashpow_cmd() {
        let cmd = Cmd {
            code: "aaa".to_string(),
            pos: 0,
            prefix: "orzz".to_string(),
            suffix: "".to_string(),
            method: HashMethod::Md5,
        };
        // 这个测试可能需要一些时间
        let _ = cmd.execute().await;
    }
}
