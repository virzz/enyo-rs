//! @alias: enc
//! @about: File encryption with AES-CTR

use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
type Aes256Ctr = Ctr128BE<aes::Aes256>;

use enyo_core::Action;

mod fileinfo;
use fileinfo::EncryptFileInfo;

const ENCRYPT_BLOCK_SIZE: usize = 1024 * 10;
const AES_BLOCK_SIZE: usize = 16;

/// AES-CTR 加密/解密 (对称操作)
fn aes_ctr_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow!("Key must be 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(anyhow!("IV must be 16 bytes"));
    }

    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

/// 检查文件是否被加密
fn check_file(filename: &str) -> Result<()> {
    let efi = EncryptFileInfo::read_file(filename)?;
    match efi {
        Some(info) => {
            println!(
                r#"Encrypted By VIRZZ
    Origin Size : {}
    Block  Size : {}
    IsCompressed: {}
    Ext         : {}"#,
                info.size,
                info.block,
                info.is_compress,
                String::from_utf8_lossy(&info.ext)
            );
        }
        None => {
            println!("Not Encrypted By virzz");
        }
    }
    Ok(())
}

/// 解密文件
fn decrypt_file(
    filename: &str,
    key: &[u8],
    iv: Option<&[u8]>,
    efi: &EncryptFileInfo,
) -> Result<()> {
    let mut file = File::options().read(true).write(true).open(filename)?;

    // 如果没有提供 IV，从文件末尾读取
    let iv = match iv {
        Some(iv) => iv.to_vec(),
        None => {
            let mut buf = vec![0u8; AES_BLOCK_SIZE];
            file.seek(SeekFrom::Start((efi.size as u64) - AES_BLOCK_SIZE as u64))?;
            file.read_exact(&mut buf)?;
            buf
        }
    };

    // 读取加密块
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = vec![0u8; efi.block as usize];
    let n = file.read(&mut buffer)?;

    // 解密
    let decrypted = aes_ctr_encrypt(&buffer[..n], key, &iv)?;

    // 写回文件
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&decrypted)?;
    file.set_len(efi.size as u64)?;

    println!("{filename} decrypted");
    Ok(())
}

/// 加密文件
fn encrypt_file(filename: &str, key: &[u8], iv: Option<&[u8]>, _compress: bool) -> Result<()> {
    // 检查是否已加密
    if let Some(efi) = EncryptFileInfo::read_file(filename)? {
        // 已加密，执行解密
        return decrypt_file(filename, key, iv, &efi);
    }

    let mut file = File::options().read(true).write(true).open(filename)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;

    // 计算加密块大小
    let mut encrypt_block_size = ENCRYPT_BLOCK_SIZE;
    while file_size < encrypt_block_size + AES_BLOCK_SIZE && encrypt_block_size > 1024 {
        encrypt_block_size -= 1024;
    }

    if file_size < encrypt_block_size + AES_BLOCK_SIZE {
        return Err(anyhow!("File size is too small"));
    }

    // 读取要加密的块
    let mut buffer = vec![0u8; encrypt_block_size];
    let n = file.read(&mut buffer)?;

    // 获取 IV (如果未提供，使用文件末尾的数据)
    let iv = match iv {
        Some(iv) => iv.to_vec(),
        None => {
            file.seek(SeekFrom::Start((file_size - AES_BLOCK_SIZE) as u64))?;
            let mut buf = vec![0u8; AES_BLOCK_SIZE];
            file.read_exact(&mut buf)?;
            buf
        }
    };

    // 加密
    let encrypted = aes_ctr_encrypt(&buffer[..n], key, &iv)?;

    // 写回文件
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&encrypted)?;

    // 写入文件信息
    file.seek(SeekFrom::End(0))?;
    let ext = PathBuf::from(filename)
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    let efi = EncryptFileInfo {
        size: file_size as u32,
        block: encrypt_block_size as u32,
        ext: ext.as_bytes().to_vec(),
        is_compress: false,
    };
    let (_, ext_data) = efi.to_bytes();
    file.write_all(&ext_data)?;

    println!("{filename} encrypted");
    Ok(())
}

#[derive(Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cmd {
    /// Secret Key (32 bytes)
    #[arg(short = 'k', long)]
    key: Option<String>,

    /// Secret IV (16 bytes)
    #[arg(long)]
    iv: Option<String>,

    /// Encrypt but not compress
    #[arg(long = "no-compress")]
    no_compress: bool,

    /// Detect whether the file is encrypted
    #[arg(short = 'c', long)]
    check: bool,

    /// File path to encrypt/decrypt
    file: String,
}

#[async_trait::async_trait]
impl Action for Cmd {
    async fn execute(&self) -> Result<()> {
        if self.check {
            return check_file(&self.file);
        }

        let key = match &self.key {
            Some(k) => k.as_bytes().to_vec(),
            None => {
                return Err(anyhow!("Key is required for encryption/decryption"));
            }
        };

        if key.len() != 32 {
            return Err(anyhow!("Key must be 32 bytes"));
        }

        let iv = self.iv.as_ref().map(|v| v.as_bytes());
        encrypt_file(&self.file, &key, iv, !self.no_compress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ctr_encrypt() {
        let data = b"hello world! this is a test message for aes-ctr encryption";
        let key = b"12345678901234567890123456789012"; // 32 bytes
        let iv = b"1234567890123456"; // 16 bytes

        let encrypted = aes_ctr_encrypt(data, key, iv).unwrap();
        let decrypted = aes_ctr_encrypt(&encrypted, key, iv).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }
}
