use anyhow::{Ok, Result};

use super::BaseX;

pub struct Base91;

impl BaseX for Base91 {
    fn encode(data: &[u8]) -> Result<String> {
        let encoded = base91::slice_encode(data);
        Ok(String::from_utf8(encoded)?)
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let data_str = std::str::from_utf8(data)?.trim();
        Ok(base91::slice_decode(data_str.as_bytes()))
    }
}
