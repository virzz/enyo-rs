use anyhow::{anyhow, Ok, Result};
use base32::{decode, encode, Alphabet};

use super::BaseX;

pub struct Base32;

impl BaseX for Base32 {
    fn encode(data: &[u8]) -> Result<String> {
        Ok(encode(Alphabet::Crockford, data))
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let data_str = std::str::from_utf8(data)?;
        let decoded = decode(Alphabet::Crockford, data_str.trim())
            .ok_or_else(|| anyhow!("Failed to decode base32"))?;
        Ok(decoded)
    }
}
