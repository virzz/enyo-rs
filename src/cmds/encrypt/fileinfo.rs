use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const VIRZZ_MAGIC: &[u8] = b"VIRZZ";

/// 加密文件信息结构
#[derive(Debug, Clone)]
pub struct EncryptFileInfo {
    pub size: u32,
    pub block: u32,
    pub ext: Vec<u8>,
    pub is_compress: bool,
}

impl EncryptFileInfo {
    /// 序列化为字节
    /// 格式:
    /// - n bytes: ext (n <= 32)
    /// - 4 bytes: block (little endian)
    /// - 4 bytes: size (little endian)
    /// - 1 byte: is_compress (0 or 1)
    /// - 1 byte: ext length
    /// - 5 bytes: "VIRZZ" magic
    pub fn to_bytes(&self) -> (usize, Vec<u8>) {
        let mut buf = Vec::new();

        // ext (最多 32 字节)
        let ext = if self.ext.len() > 32 {
            &self.ext[..32]
        } else {
            &self.ext
        };
        buf.extend_from_slice(ext);

        // block (4 bytes, little endian)
        buf.extend_from_slice(&self.block.to_le_bytes());

        // size (4 bytes, little endian)
        buf.extend_from_slice(&self.size.to_le_bytes());

        // is_compress (1 byte)
        buf.push(if self.is_compress { 1 } else { 0 });

        // ext length (1 byte)
        buf.push(ext.len() as u8);

        // magic (5 bytes)
        buf.extend_from_slice(VIRZZ_MAGIC);

        (buf.len(), buf)
    }

    /// 从字节解析
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        // 检查 magic
        if !data.ends_with(VIRZZ_MAGIC) {
            return None;
        }

        let len = data.len();
        if len < 15 {
            return None;
        }

        let ext_size = data[len - 6] as usize;
        let is_compress = data[len - 7] == 1;

        // size (4 bytes, little endian)
        let size = u32::from_le_bytes([data[len - 11], data[len - 10], data[len - 9], data[len - 8]]);

        // block (4 bytes, little endian)  
        let block = u32::from_le_bytes([data[len - 15], data[len - 14], data[len - 13], data[len - 12]]);

        // ext
        let ext_start = len - 15 - ext_size;
        let ext = data[ext_start..len - 15].to_vec();

        Some(Self {
            size,
            block,
            ext,
            is_compress,
        })
    }

    /// 从文件读取加密信息
    pub fn read_file(path: &str) -> Result<Option<Self>> {
        let mut file = File::open(path)?;

        // 读取文件末尾 55 字节
        file.seek(SeekFrom::End(-55))?;
        let mut buf = vec![0u8; 55];
        file.read_exact(&mut buf)?;

        Ok(Self::from_bytes(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_file_info() {
        let efi = EncryptFileInfo {
            size: 234,
            block: 764423,
            ext: b"png".to_vec(),
            is_compress: true,
        };

        let (n, data) = efi.to_bytes();
        println!("Length: {n}, Data: {data:?}");

        let parsed = EncryptFileInfo::from_bytes(&data).unwrap();
        assert_eq!(parsed.size, efi.size);
        assert_eq!(parsed.block, efi.block);
        assert_eq!(parsed.ext, efi.ext);
        assert_eq!(parsed.is_compress, efi.is_compress);
    }

    #[test]
    fn test_not_encrypted() {
        let data = b"this is not encrypted data";
        assert!(EncryptFileInfo::from_bytes(data).is_none());
    }
}

