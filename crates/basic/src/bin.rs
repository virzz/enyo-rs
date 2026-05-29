use anyhow::Result;

/// 处理 hex 字符串前缀
fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// 添加 0x 前缀
fn pad_hex(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_string()
    } else {
        format!("0x{s}")
    }
}

/// Bin -> Hex (将二进制数据转为十六进制)
pub fn bin_to_hex(data: &[u8]) -> Result<String> {
    Ok(pad_hex(&hex::encode(data)))
}

/// Hex -> Bin (将十六进制字符串转为二进制数据)
pub fn hex_to_bin(s: &str) -> Result<Vec<u8>> {
    let s = strip_hex_prefix(s.trim());
    Ok(hex::decode(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bin_to_hex() {
        let result = bin_to_hex(b"100101000101011101").unwrap();
        println!("Bin to Hex: {result}");
        assert!(result.starts_with("0x"));
    }

    #[test]
    fn test_hex_to_bin() {
        let result = hex_to_bin("0x0cc175b9c0f1b6a831c399e269772661").unwrap();
        println!("Hex to Bin: {:?}", String::from_utf8_lossy(&result));
    }

    #[test]
    fn test_hex_to_bin_no_prefix() {
        let result = hex_to_bin("48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }
}
