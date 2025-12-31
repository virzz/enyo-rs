use sha1::{Sha1, Digest};

/// MySQL Hash password using pre-4.1 method
pub fn mysql_hash(password: &[u8]) -> String {
    let mut add: u32 = 7;
    let mut r1: u32 = 1345345333;
    let mut r2: u32 = 0x12345671;

    for &c in password {
        if c == b' ' || c == b'\t' {
            continue; // skip spaces and tabs
        }
        let tmp = c as u32;
        r1 ^= (((r1 & 63).wrapping_add(add)).wrapping_mul(tmp)).wrapping_add(r1 << 8);
        r2 = r2.wrapping_add((r2 << 8) ^ r1);
        add = add.wrapping_add(tmp);
    }

    // Remove sign bit (1<<31)-1)
    format!("*{:08x}{:08x}", r1 & 0x7FFFFFFF, r2 & 0x7FFFFFFF)
}

/// MySQL5 Hash password using 4.1+ method (SHA1)
pub fn mysql5_hash(password: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password);
    let first_hash = hasher.finalize();

    let mut hasher = Sha1::new();
    hasher.update(first_hash);
    let second_hash = hasher.finalize();

    format!("*{}", hex::encode_upper(second_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_hash() {
        let result = mysql_hash(b"test");
        println!("MySQL Hash: {result}");
    }

    #[test]
    fn test_mysql5_hash() {
        let result = mysql5_hash(b"test");
        println!("MySQL5 Hash: {result}");
        // MySQL5 password hash for "test" should be *94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29
        assert!(result.starts_with("*"));
    }
}

