use md4::{Md4, Digest};

/// Convert bytes to UTF-16LE encoding
fn utf16le(s: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(s.len() * 2);
    for &b in s {
        result.push(b);
        result.push(0);
    }
    result
}

/// NTLM Hash (MD4 of UTF-16LE encoded password)
pub fn ntlm_hash(password: &[u8]) -> String {
    let utf16 = utf16le(password);
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_hash() {
        let result = ntlm_hash(b"testasdvafsd");
        println!("NTLM Hash: {result}");
    }

    #[test]
    fn test_ntlm_hash_empty() {
        let result = ntlm_hash(b"");
        println!("NTLM Hash (empty): {result}");
        // Empty string NTLM hash
        assert_eq!(result, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_utf16le() {
        let result = utf16le(b"test");
        assert_eq!(result, vec![b't', 0, b'e', 0, b's', 0, b't', 0]);
    }
}

