use anyhow::{Ok, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine,
};

use super::BaseX;

pub struct Base64Standard;
pub struct Base64UrlSafe;

impl BaseX for Base64Standard {
    fn encode(data: &[u8]) -> Result<String> {
        Ok(STANDARD.encode(data))
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let data_str = std::str::from_utf8(data)?;
        let decoded = STANDARD.decode(data_str.trim())?;
        Ok(decoded)
    }
}

impl BaseX for Base64UrlSafe {
    fn encode(data: &[u8]) -> Result<String> {
        Ok(URL_SAFE.encode(data))
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let data_str = std::str::from_utf8(data)?;
        let decoded = URL_SAFE.decode(data_str.trim())?;
        Ok(decoded)
    }
}
