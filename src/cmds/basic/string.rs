use anyhow::{anyhow, Result};
use rand::Rng;
use regex::Regex;

use super::bin::{hex_to_bin, bin_to_hex};

/// 处理 hex 字符串前缀
fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)
}

/// 添加 0x 前缀
fn pad_hex(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_string()
    } else {
        format!("0x{s}")
    }
}

/// String -> ASCII (字符串转ASCII码，逗号分隔)
pub fn string_to_ascii(s: &str) -> Result<String> {
    let ascii_values: Vec<String> = s.chars().map(|c| (c as u32).to_string()).collect();
    Ok(ascii_values.join(","))
}

/// ASCII -> String (逗号分隔的ASCII码转字符串)
pub fn ascii_to_string(s: &str) -> Result<String> {
    let parts: Vec<&str> = s.trim().split(',').collect();
    let mut result = String::new();
    for part in parts {
        match part.trim().parse::<u32>() {
            Ok(code) => {
                if let Some(c) = char::from_u32(code) {
                    result.push(c);
                } else {
                    result.push('?');
                }
            }
            Err(_) => result.push('?'),
        }
    }
    Ok(result)
}

/// Hex -> String (十六进制转字符串)
pub fn hex_to_string(s: &str) -> Result<String> {
    let bytes = hex_to_bin(s)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// String -> Hex (字符串转十六进制)
pub fn string_to_hex(s: &str) -> Result<String> {
    bin_to_hex(s.as_bytes())
}

/// Dec -> Hex (十进制转十六进制，支持大数)
pub fn dec_to_hex(s: &str) -> Result<String> {
    let s = s.trim();
    // 支持大数
    let n: u128 = s.parse().map_err(|_| anyhow!("Invalid decimal number"))?;
    Ok(pad_hex(&format!("{n:x}")))
}

/// Hex -> Dec (十六进制转十进制，支持大数)
pub fn hex_to_dec(s: &str) -> Result<String> {
    let s = strip_hex_prefix(s.trim());
    let n = u128::from_str_radix(s, 16).map_err(|_| anyhow!("Invalid hex number"))?;
    Ok(n.to_string())
}

/// Hex -> Bytes String (十六进制转字节字符串 b'...')
/// 可见字符直接显示，不可见字符用 \xXX 表示
pub fn hex_to_byte_string(s: &str) -> Result<String> {
    let bytes = hex_to_bin(s)?;
    let mut result = String::new();
    for b in bytes {
        if (0x20..=0x7E).contains(&b) {
            result.push(b as char);
        } else {
            result.push_str(&format!("\\x{b:02x}"));
        }
    }
    Ok(format!("b'{result}'"))
}

/// Bytes String -> Hex (字节字符串转十六进制)
/// 解析 b'...' 或 b"..." 格式
pub fn byte_string_to_hex(s: &str) -> Result<String> {
    let re = Regex::new(r#"^b["']([\S\s]*?)['"]$"#)?;
    let captures = re.captures(s).ok_or_else(|| anyhow!("Invalid byte string format"))?;
    let content = captures.get(1).map_or("", |m| m.as_str());

    let mut result = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 3 < chars.len() && chars[i + 1] == 'x' {
            // \xXX 格式
            let hex_str: String = chars[i + 2..i + 4].iter().collect();
            if let Ok(b) = u8::from_str_radix(&hex_str, 16) {
                result.push(b);
            }
            i += 4;
        } else {
            result.push(chars[i] as u8);
            i += 1;
        }
    }
    bin_to_hex(&result)
}

/// Bytes String -> String (字节字符串转字符串)
pub fn byte_string_to_string(s: &str) -> Result<String> {
    let hex = byte_string_to_hex(s)?;
    hex_to_string(&hex)
}

/// 根据正则表达式生成指定长度的随机字符串
pub fn random_string(length: usize, charset_pattern: &str) -> Result<String> {
    let charset = expand_charset(charset_pattern)?;
    if charset.is_empty() {
        return Err(anyhow!("Empty charset"));
    }

    let mut rng = rand::rng();
    let result: String = (0..length)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect();
    Ok(result)
}

/// 展开字符集模式 (如 "a-z0-9" -> ['a', 'b', ..., 'z', '0', ..., '9'])
fn expand_charset(pattern: &str) -> Result<Vec<u8>> {
    let mut charset = Vec::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if i + 2 < chars.len() && chars[i + 1] == '-' {
            // 范围模式 a-z
            let start = chars[i] as u8;
            let end = chars[i + 2] as u8;
            if start <= end {
                for c in start..=end {
                    charset.push(c);
                }
            }
            i += 3;
        } else {
            charset.push(chars[i] as u8);
            i += 1;
        }
    }
    Ok(charset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_to_ascii() {
        let result = string_to_ascii("test_string_virzz").unwrap();
        assert_eq!(result, "116,101,115,116,95,115,116,114,105,110,103,95,118,105,114,122,122");
        println!("String to ASCII: {result}");
    }

    #[test]
    fn test_ascii_to_string() {
        let result = ascii_to_string("116,101,115,116,95,115,116,114,105,110,103,95,118,105,114,122,122").unwrap();
        assert_eq!(result, "test_string_virzz");
        println!("ASCII to String: {result}");
    }

    #[test]
    fn test_hex_to_string() {
        let result = hex_to_string("0x746573745f737472696e675f7669727a7a").unwrap();
        assert_eq!(result, "test_string_virzz");
        println!("Hex to String: {result}");
    }

    #[test]
    fn test_string_to_hex() {
        let result = string_to_hex("test_string_virzz").unwrap();
        assert_eq!(result, "0x746573745f737472696e675f7669727a7a");
        println!("String to Hex: {result}");
    }

    #[test]
    fn test_dec_to_hex() {
        let result = dec_to_hex("1234567890987654321").unwrap();
        assert_eq!(result, "0x112210f4b16c1cb1");
        println!("Dec to Hex: {result}");
    }

    #[test]
    fn test_hex_to_dec() {
        let result = hex_to_dec("0x112210f4b16c1cb1").unwrap();
        assert_eq!(result, "1234567890987654321");
        println!("Hex to Dec: {result}");
    }

    #[test]
    fn test_hex_to_byte_string() {
        let result = hex_to_byte_string("0x746573745f11aa22bb33cc44dd55ee66ff7788995f737472696e67").unwrap();
        println!("Hex to Byte String: {result}");
        assert!(result.starts_with("b'test_"));
    }

    #[test]
    fn test_byte_string_to_hex() {
        let result = byte_string_to_hex(r#"b'test_\x11\xaa"\xbb3\xccD\xddU\xeef\xffw\x88\x99_string'"#).unwrap();
        assert_eq!(result, "0x746573745f11aa22bb33cc44dd55ee66ff7788995f737472696e67");
        println!("Byte String to Hex: {result}");
    }

    #[test]
    fn test_byte_string_to_string() {
        let result = byte_string_to_string(r#"b'hello world'"#).unwrap();
        assert_eq!(result, "hello world");
        println!("Byte String to String: {result}");
    }

    #[test]
    fn test_random_string() {
        let result = random_string(16, "a-z0-9").unwrap();
        assert_eq!(result.len(), 16);
        println!("Random String: {result}");
    }

    #[test]
    fn test_random_string_upper() {
        let result = random_string(8, "A-Z").unwrap();
        assert!(result.chars().all(|c| c.is_ascii_uppercase()));
        println!("Random String (upper): {result}");
    }

    #[test]
    fn test_expand_charset() {
        let charset = expand_charset("a-z").unwrap();
        assert_eq!(charset.len(), 26);

        let charset = expand_charset("0-9").unwrap();
        assert_eq!(charset.len(), 10);

        let charset = expand_charset("a-z0-9").unwrap();
        assert_eq!(charset.len(), 36);
    }
}

