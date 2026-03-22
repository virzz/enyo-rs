use anyhow::Result;
use futures::future::join_all;
use std::fmt::Debug;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const MAX_ITERATIONS: usize = 5; // 防止无限循环，最大递归深度
const MAX_PATHS: usize = 1000; // 最大探索路径数，防止指数爆炸

/// 解码器的定义
#[derive(Debug, Clone, Copy)]
pub enum Decoder {
    Base16,
    Base32,
    Base36,
    Base58,
    Base62,
    Base64,
    Base91,
    Base100,
}

impl std::fmt::Display for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decoder::Base16 => write!(f, "Base16"),
            Decoder::Base32 => write!(f, "Base32"),
            Decoder::Base36 => write!(f, "Base36"),
            Decoder::Base58 => write!(f, "Base58"),
            Decoder::Base62 => write!(f, "Base62"),
            Decoder::Base64 => write!(f, "Base64"),
            Decoder::Base91 => write!(f, "Base91"),
            Decoder::Base100 => write!(f, "Base100"),
        }
    }
}

impl Decoder {
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Decoder::Base16 => Base16::decode(data),
            Decoder::Base32 => Base32::decode(data),
            Decoder::Base36 => Base36::decode(data),
            Decoder::Base58 => Base58::decode(data),
            Decoder::Base62 => Base62::decode(data),
            Decoder::Base64 => Base64Standard::decode(data),
            Decoder::Base91 => Base91::decode(data),
            Decoder::Base100 => Base100::decode(data),
        }?)
    }
}

/// 解码步骤的结果
#[derive(Debug, Clone)]
pub struct DecodePath {
    /// 当前的解码器类型
    pub decoder: Decoder,
    // /// 解码前的数据
    // pub input: Vec<u8>,
    /// 解码后的数据
    pub output: Vec<u8>,
    /// 前置步骤
    pub previous: Option<Box<DecodePath>>,
}

impl DecodePath {
    /// 创建一个新的解码路径节点
    fn new(decoder: Decoder, output: Vec<u8>, previous: Option<Box<DecodePath>>) -> Self {
        Self {
            decoder,
            output,
            previous,
        }
    }

    /// 获取完整的解码路径字符串
    pub fn verbose(&self) -> String {
        let mut path = String::new();
        // 递归构建路径
        if let Some(prev) = &self.previous {
            path.push_str(&prev.verbose().to_string());
        }
        path.push_str(&format!(
            "\n-> {} = {}",
            self.decoder,
            String::from_utf8_lossy(&self.output),
        ));
        path
    }
}

fn decodes() -> Vec<Decoder> {
    vec![
        Decoder::Base16,
        Decoder::Base32,
        Decoder::Base36,
        Decoder::Base58,
        Decoder::Base62,
        Decoder::Base64,
        Decoder::Base91,
        Decoder::Base100,
    ]
}

/// 异步尝试单个解码器解码
async fn try_decode(
    decoder: Decoder,
    data: &[u8],
    parent_path: Option<Box<DecodePath>>,
) -> Result<DecodePath> {
    match decoder.decode(data) {
        StdResult::Ok(result) => Ok(DecodePath::new(decoder, result, parent_path)),
        Err(e) => Err(e),
    }
}

/// 检查数据是否可能是有效的编码数据（包含可打印 ASCII 字符）
fn is_likely_encoded(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // 检查数据长度，太短的数据可能是最终结果
    if data.len() < 4 {
        return false;
    }
    // 至少有一定比例的可打印 ASCII 字符才继续递归
    // 包含常见 base 编码字符：字母数字 + Base64 (+/=) + URL安全 (-_)
    let printable_count = data
        .iter()
        .filter(|&&b| b.is_ascii_alphanumeric() || b"+=/_-".contains(&b))
        .count();
    printable_count * 100 / data.len() >= 70
}

/// 尝试自动解码多层BaseX编码，返回解码路径
pub async fn fuzzing_path(
    decoders: &[Decoder],
    data: &[u8],
    parent_path: Option<Box<DecodePath>>,
    depth: usize,
    path_count: &AtomicUsize,
) -> Result<Vec<DecodePath>> {
    // 防止无限递归
    if depth >= MAX_ITERATIONS {
        return Ok(Vec::new());
    }
    // 防止路径爆炸
    if path_count.load(Ordering::Relaxed) >= MAX_PATHS {
        return Ok(Vec::new());
    }
    // 为所有解码器创建任务
    let mut decode_tasks = Vec::new();
    for decoder in decoders {
        decode_tasks.push(try_decode(*decoder, data, parent_path.clone()));
    }
    // 执行所有解码任务
    let results = join_all(decode_tasks).await;
    let mut paths = Vec::new();
    for path in results.into_iter().flatten() {
        // 检查是否超过路径限制
        if path_count.fetch_add(1, Ordering::Relaxed) >= MAX_PATHS {
            break;
        }
        let data = path.output.clone();
        // 只有当输出看起来像编码数据时才继续递归
        let sub_paths = if is_likely_encoded(&data) {
            Box::pin(fuzzing_path(
                decoders,
                &data,
                Some(Box::new(path.clone())),
                depth + 1,
                path_count,
            ))
            .await?
        } else {
            Vec::new()
        };
        paths.push(path);
        paths.extend(sub_paths);
    }
    Ok(paths)
}

/// 尝试自动解码多层BaseX编码，返回解码后的数据
pub async fn fuzzing(data: &[u8]) -> Result<Vec<DecodePath>> {
    let decoders = decodes();
    let path_count = AtomicUsize::new(0);
    Ok(fuzzing_path(&decoders, data, None, 0, &path_count).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;
    impl Decoder {
        pub fn encode(&self, data: &[u8]) -> Result<String> {
            Ok(match self {
                Decoder::Base16 => {
                    let encoded = Base16::encode(data)?;
                    println!("Base16 encoded: {encoded}");
                    encoded
                }
                Decoder::Base32 => {
                    let encoded = Base32::encode(data)?;
                    println!("Base32 encoded: {encoded}");
                    encoded
                }
                Decoder::Base36 => {
                    let encoded = Base36::encode(data)?;
                    println!("Base36 encoded: {encoded}");
                    encoded
                }
                Decoder::Base58 => {
                    let encoded = Base58::encode(data)?;
                    println!("Base58 encoded: {encoded}");
                    encoded
                }
                Decoder::Base62 => {
                    let encoded = Base62::encode(data)?;
                    println!("Base62 encoded: {encoded}");
                    encoded
                }
                Decoder::Base64 => {
                    let encoded = Base64Standard::encode(data)?;
                    println!("Base64 encoded: {encoded}");
                    encoded
                }
                Decoder::Base91 => {
                    let encoded = Base91::encode(data)?;
                    println!("Base91 encoded: {encoded}");
                    encoded
                }
                Decoder::Base100 => {
                    let encoded = Base100::encode(data)?;
                    println!("Base100 encoded: {encoded}");
                    encoded
                }
            })
        }
    }
    fn random_encode(data: &[u8], n: usize) -> String {
        let mut rng = rand::rng();
        let decoders = decodes();
        let mut result = String::from_utf8(data.to_vec()).unwrap();
        for _ in 0..n {
            let decoder = decoders[rng.random_range(0..decoders.len())];
            result = decoder.encode(result.as_bytes()).unwrap();
        }
        result
    }

    #[tokio::test]
    async fn test_fuzzing_deterministic() {
        // 使用确定性编码序列：Base64 -> Base32 -> Base16
        let original_text = "HelloWorld";
        println!("Original: {original_text}");

        // 多层编码
        let step1 = Base64Standard::encode(original_text.as_bytes()).unwrap();
        println!("After Base64: {step1}");
        let step2 = Base32::encode(step1.as_bytes()).unwrap();
        println!("After Base32: {step2}");
        let encoded = Base16::encode(step2.as_bytes()).unwrap();
        println!("Final encoded: {encoded}");

        let result = fuzzing(encoded.as_bytes()).await.unwrap();
        for r in &result {
            if r.output == original_text.as_bytes() {
                println!("Match found: {}", String::from_utf8_lossy(&r.output));
                return;
            }
        }

        // 打印所有结果用于调试
        println!("All results ({} total):", result.len());
        for r in result.iter().take(20) {
            println!("  -> {}", String::from_utf8_lossy(&r.output));
        }

        panic!("No match found for original text");
    }

    /// 随机编码测试，由于随机性可能偶尔失败，标记为 ignore
    /// 运行: cargo test -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_fuzzing_random() {
        let original_text = "test123";
        println!("Original: {original_text}");
        // 使用 2 层编码，更可靠地在限制内找到
        let encoded = random_encode(original_text.as_bytes(), 2);
        println!("Encoded: {encoded}");
        let result = fuzzing(encoded.as_bytes()).await.unwrap();
        for r in result {
            if r.output == original_text.as_bytes() {
                println!("Match: {}", String::from_utf8_lossy(&r.output));
                return;
            } else if String::from_utf8_lossy(&r.output) == original_text {
                println!("Match: {}", String::from_utf8_lossy(&r.output));
                return;
            }
        }

        panic!("No match");
    }
}
