use anyhow::Result;

/// XOR two byte slices
pub fn xor(first: &str, second: &str) -> Result<String> {
    let first_bytes = first.as_bytes();
    let second_bytes = second.as_bytes();

    let len = first_bytes.len().min(second_bytes.len());
    let result: Vec<u8> = (0..len).map(|i| first_bytes[i] ^ second_bytes[i]).collect();

    Ok(String::from_utf8_lossy(&result).to_string())
}

/// XOR bytes with a key (循环使用 key)
#[allow(dead_code)]
pub fn xor_with_key(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let result = xor("aaaa", "1111").unwrap();
        println!("XOR aaaa ^ 1111 = {result}");
        assert_eq!(result, "PPPP");
    }

    #[test]
    fn test_xor_pppp() {
        let result = xor("PPPP", "1111").unwrap();
        println!("XOR PPPP ^ 1111 = {result}");
        assert_eq!(result, "aaaa");
    }

    #[test]
    fn test_xor_different_length() {
        let result = xor("abcdefaerfbgaer", "barbgeargvaerg").unwrap();
        println!("XOR result: {result}");
    }

    #[test]
    fn test_xor_with_key() {
        let data = b"hello world";
        let key = b"key";
        let encrypted = xor_with_key(data, key);
        let decrypted = xor_with_key(&encrypted, key);
        assert_eq!(decrypted, data);
    }
}
