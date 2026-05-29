use anyhow::{Ok, Result};

use super::BaseX;

pub struct Base16;

impl BaseX for Base16 {
    fn encode(data: &[u8]) -> Result<String> {
        Ok(hex::encode(data))
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let bytes = hex::decode(data)?;
        Ok(bytes)
    }
}
