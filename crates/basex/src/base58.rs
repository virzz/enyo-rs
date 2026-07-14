use super::BaseX;
use anyhow::{Ok, Result};

pub struct Base58;

impl BaseX for Base58 {
    fn encode(data: &[u8]) -> Result<String> {
        Ok(bs58::encode(data).into_string())
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let data_str = std::str::from_utf8(data)?;
        let decoded = bs58::decode(data_str.trim()).into_vec()?;
        Ok(decoded)
    }
}
