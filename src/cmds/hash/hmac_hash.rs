use anyhow::Result;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
#[allow(unused_imports)]
use md5::Digest;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

use super::{Sha2Type, Sha3Type};

type HmacMd4 = Hmac<Md4>;
type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha224 = Hmac<Sha224>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;
type HmacSha512_224 = Hmac<Sha512_224>;
type HmacSha512_256 = Hmac<Sha512_256>;
type HmacSha3_224 = Hmac<Sha3_224>;
type HmacSha3_256 = Hmac<Sha3_256>;
type HmacSha3_384 = Hmac<Sha3_384>;
type HmacSha3_512 = Hmac<Sha3_512>;
type HmacRipemd160 = Hmac<Ripemd160>;

/// HMAC-MD4
pub fn hmac_md4(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacMd4::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// HMAC-MD5
pub fn hmac_md5(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacMd5::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// HMAC-SHA1
pub fn hmac_sha1(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha1::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// HMAC-SHA2 family
pub fn hmac_sha2(data: &[u8], key: &[u8], hash_type: &Sha2Type) -> Result<Vec<u8>> {
    match hash_type {
        Sha2Type::Sha224 => {
            let mut mac = HmacSha224::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha2Type::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha2Type::Sha384 => {
            let mut mac = HmacSha384::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha2Type::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha2Type::Sha512_224 => {
            let mut mac = HmacSha512_224::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha2Type::Sha512_256 => {
            let mut mac = HmacSha512_256::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// HMAC-SHA3 family
pub fn hmac_sha3(data: &[u8], key: &[u8], hash_type: &Sha3Type) -> Result<Vec<u8>> {
    match hash_type {
        Sha3Type::Sha3_224 => {
            let mut mac = HmacSha3_224::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha3Type::Sha3_256 => {
            let mut mac = HmacSha3_256::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha3Type::Sha3_384 => {
            let mut mac = HmacSha3_384::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Sha3Type::Sha3_512 => {
            let mut mac = HmacSha3_512::new_from_slice(key)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// HMAC-RIPEMD160
pub fn hmac_ripemd160(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacRipemd160::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_md5() {
        let result = hmac_md5(b"test", b"key").unwrap();
        println!("HMAC-MD5: {}", hex::encode(&result));
    }

    #[test]
    fn test_hmac_sha256() {
        let result = hmac_sha2(b"test", b"key", &Sha2Type::Sha256).unwrap();
        println!("HMAC-SHA256: {}", hex::encode(&result));
    }
}

