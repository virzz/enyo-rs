use anyhow::{Ok, Result};

use super::BaseX;

pub struct Base100;

/// Base100 (emoji) encoding implementation
/// Each byte is encoded as a 4-byte UTF-8 emoji sequence
impl BaseX for Base100 {
    fn encode(data: &[u8]) -> Result<String> {
        let mut out = Vec::with_capacity(data.len() * 4);
        for ch in data {
            out.push(0xf0);
            out.push(0x9f);
            // (ch + 55) >> 6 approximates (ch + 55) / 64
            out.push((((*ch as u16).wrapping_add(55)) >> 6) as u8 + 143);
            // (ch + 55) & 0x3f approximates (ch + 55) % 64
            out.push((ch.wrapping_add(55) & 0x3f).wrapping_add(128));
        }
        Ok(String::from_utf8(out)?)
    }

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len() / 4);
        for chunk in data.chunks(4) {
            if chunk.len() == 4 {
                // Decode: ((chunk[2] - 143) * 64) + (chunk[3] - 128) - 55
                let byte = ((chunk[2].wrapping_sub(143)).wrapping_mul(64))
                    .wrapping_add(chunk[3].wrapping_sub(128))
                    .wrapping_sub(55);
                out.push(byte);
            }
        }
        Ok(out)
    }
}
