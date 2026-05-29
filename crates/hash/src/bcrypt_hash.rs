use anyhow::{anyhow, Result};
use bcrypt::{hash, verify};

/// Generate bcrypt hash
pub fn bcrypt_generate(password: &str, cost: u32) -> Result<String> {
    let cost = cost.clamp(4, 31);
    let hashed = hash(password, cost)?;
    Ok(hashed)
}

/// Compare bcrypt hash with password
pub fn bcrypt_compare(hashed: &str, password: &str) -> Result<()> {
    // 尝试两种顺序比较（和 Go 版本保持一致）
    if verify(password, hashed).unwrap_or(false) {
        return Ok(());
    }
    if verify(hashed, password).unwrap_or(false) {
        return Ok(());
    }
    Err(anyhow!("Password does not match"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "aewgvrweasgw";
    const HASHED: &str = "$2a$10$dmBwjxKqfD2T4n/pAaaQ2ePNHFp8U9GMes5XNfKUC8ssezx2y/2Ci";

    #[test]
    fn test_bcrypt_generate() {
        let result = bcrypt_generate(PASSWORD, 10).unwrap();
        println!("Bcrypt hash: {result}");
        assert!(result.starts_with("$2"));
    }

    #[test]
    fn test_bcrypt_compare() {
        let result = bcrypt_compare(HASHED, PASSWORD);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bcrypt_compare_fail() {
        let result = bcrypt_compare(HASHED, "wrongpassword");
        assert!(result.is_err());
    }
}
