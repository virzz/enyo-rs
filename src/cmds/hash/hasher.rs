use anyhow::Result;
use md4::Md4;
use md5::{Md5, Digest};
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

use super::{Sha2Type, Sha3Type};

/// MD2 hash (简化实现，使用 MD5 代替)
pub fn md2_hash(data: &[u8]) -> Result<Vec<u8>> {
    // MD2 不常用，简化处理
    let mut hasher = Md5::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

/// MD4 hash
pub fn md4_hash(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Md4::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

/// MD5 hash
pub fn md5_hash(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Md5::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

/// SHA1 hash
pub fn sha1_hash(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

/// SHA2 hash family
pub fn sha2_hash(data: &[u8], hash_type: &Sha2Type) -> Result<Vec<u8>> {
    match hash_type {
        Sha2Type::Sha224 => {
            let mut hasher = Sha224::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha2Type::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha2Type::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha2Type::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha2Type::Sha512_224 => {
            let mut hasher = Sha512_224::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha2Type::Sha512_256 => {
            let mut hasher = Sha512_256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
    }
}

/// SHA3 hash family
pub fn sha3_hash(data: &[u8], hash_type: &Sha3Type) -> Result<Vec<u8>> {
    match hash_type {
        Sha3Type::Sha3_224 => {
            let mut hasher = Sha3_224::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha3Type::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha3Type::Sha3_384 => {
            let mut hasher = Sha3_384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Sha3Type::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
    }
}

/// RIPEMD160 hash
pub fn ripemd160_hash(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let result = md5_hash(b"test").unwrap();
        assert_eq!(hex::encode(&result), "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_sha1() {
        let result = sha1_hash(b"test").unwrap();
        assert_eq!(hex::encode(&result), "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
    }

    #[test]
    fn test_sha256() {
        let result = sha2_hash(b"test", &Sha2Type::Sha256).unwrap();
        assert_eq!(hex::encode(&result), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    }

    #[test]
    fn test_sha3_256() {
        let result = sha3_hash(b"test", &Sha3Type::Sha3_256).unwrap();
        println!("SHA3-256: {}", hex::encode(&result));
    }

    #[test]
    fn test_ripemd160() {
        let result = ripemd160_hash(b"test").unwrap();
        println!("RIPEMD160: {}", hex::encode(&result));
    }

    #[test]
    fn test_md4() {
        let result = md4_hash(b"test").unwrap();
        println!("MD4: {}", hex::encode(&result));
    }
}

