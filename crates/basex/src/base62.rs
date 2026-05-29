use anyhow::{anyhow, Ok, Result};

use super::BaseX;

pub struct Base62;

impl BaseX for Base62 {
    fn encode(data: &[u8]) -> Result<String> {
        if data.is_empty() {
            return Ok(String::new());
        }
        let mut result = Vec::new();
        for chunk in data.chunks(15) {
            let mut value: u128 = 0;
            value |= (chunk.len() as u128) << 120;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u128) << (i * 8);
            }
            result.push(base62::encode(value));
        }
        Ok(result.join("_"))
    }
    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let data_str = std::str::from_utf8(data)?.trim();
        if !data_str.contains('_') {
            let decoded_u128 = base62::decode(data_str)?;
            return u128_to_bytes(decoded_u128);
        }
        let mut result = Vec::new();
        for chunk_str in data_str.split('_') {
            if chunk_str.is_empty() {
                continue;
            }
            let chunk_value = base62::decode(chunk_str)?;
            let length = ((chunk_value >> 120) & 0xFF) as usize;
            if length == 0 || length > 15 {
                return Err(anyhow!("无效的数据块长度标记"));
            }
            for i in 0..length {
                let byte = ((chunk_value >> (i * 8)) & 0xFF) as u8;
                result.push(byte);
            }
        }
        Ok(result)
    }
}

fn u128_to_bytes(mut value: u128) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    if value == 0 {
        result.push(0);
        return Ok(result);
    }
    while value > 0 {
        result.push((value & 0xFF) as u8);
        value >>= 8;
    }
    Ok(result)
}
