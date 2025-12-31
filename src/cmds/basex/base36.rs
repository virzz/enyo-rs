use anyhow::{Ok, Result};
use base_x;

use super::BaseX;

pub struct Base36;

impl BaseX for Base36 {
    fn encode(data: &[u8]) -> Result<String> {
        Ok(base_x::encode("0123456789abcdefghijklmnopqrstuvwxyz", data))
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let data_str = std::str::from_utf8(data)?;
        let decoded = base_x::decode("0123456789abcdefghijklmnopqrstuvwxyz", data_str.trim())?;
        Ok(decoded)
    }
}
