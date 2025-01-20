use std::{
    fs::{self, File},
    io::Read,
    path::PathBuf,
};

use clap::{Parser, ValueEnum};

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use anyhow::Result;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;
use sha2::Sha512;

#[derive(Parser)]
#[command(name = "wechat")]
pub struct Args {
    #[arg(short = 'v', help = "wechat db file version")]
    ver: Option<WechatDbType>,

    #[arg(short = 'k', help = "key for offline decryption of db file")]
    key: String,

    #[arg(short = 'f', help = "special a db file path")]
    file: PathBuf,

    #[arg(short = 'r', help = "convert db key to sqlcipher raw key")]
    rawkey: bool,
}

#[derive(Clone, ValueEnum)]
enum WechatDbType {
    V3,
    V4,
}

const KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const HMAC_SHA1_SIZE: usize = 20;
const AES_BLOCK_SIZE: usize = 16;
const HMAC_SHA256_SIZE: usize = 64;
const PAGE_SIZE: usize = 4096;
const ROUND_COUNT_V3: u32 = 64000;
const ROUND_COUNT_V4: u32 = 256000;
const SQLITE_HEADER: &str = "SQLite format 3";

type HamcSha512 = Hmac<Sha512>;
type HamcSha1 = Hmac<Sha1>;

// fn decrypt_db_file_v3(path: &PathBuf, pkey: &String) -> Result<Vec<u8>> {
//     let mut buf = read_file_content(path)?;
//     // 如果开头是 SQLITE_HEADER，说明不需要解密
//     if buf.starts_with(SQLITE_HEADER.as_bytes()) {
//         return Ok(buf);
//     }
//     let mut decrypted_buf: Vec<u8> = vec![];
//     // 获取到文件开头的 salt，用于解密 key
//     let salt = buf[..16].to_owned();
//     // salt 异或 0x3a 得到 mac_salt， 用于计算HMAC
//     let mac_salt: Vec<u8> = salt.to_owned().iter().map(|x| x ^ 0x3a).collect();
//     unsafe {
//         // 通过 pkey 和 salt 迭代 ROUND_COUNT_V3 次解出一个新的 key，用于解密
//         let pass = hex::decode(pkey)?;
//         let key = pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&pass, &salt, ROUND_COUNT_V3);
//         // 通过 key 和 mac_salt 迭代2次解出 mac_key
//         let mac_key = pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&key, &mac_salt, 2);
//         // 开头是 sqlite 头
//         decrypted_buf.extend(SQLITE_HEADER.as_bytes());
//         decrypted_buf.push(0x00);
//         // hash检验码对齐后长度 48，后面校验哈希用
//         let mut reserve = IV_SIZE + HMAC_SHA1_SIZE;
//         reserve = if (reserve % AES_BLOCK_SIZE) == 0 {
//             reserve
//         } else {
//             ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
//         };
//         // 每页大小4096，分别解密
//         let total_page = buf.len() / PAGE_SIZE;
//         for cur_page in 0..total_page {
//             let offset = if cur_page == 0 { SALT_SIZE } else { 0 };
//             let start: usize = cur_page * PAGE_SIZE;
//             let end: usize = start + PAGE_SIZE;
//             // 搞不懂，这一堆0是干啥的，文件大小直接翻倍了
//             if buf[start..end].iter().all(|&x| x == 0) {
//                 decrypted_buf.extend(&buf[start..]);
//                 break;
//             }
//             // 校验哈希
//             let mut mac = HamcSha1::new_from_slice(&mac_key)?;
//             mac.update(&buf[start + offset..end - reserve + IV_SIZE]);
//             mac.update(std::mem::transmute::<_, &[u8; 4]>(&(cur_page as u32 + 1)).as_ref());
//             let hash_mac = mac.finalize().into_bytes().to_vec();
//             let hash_mac_start_offset = end - reserve + IV_SIZE;
//             let hash_mac_end_offset = hash_mac_start_offset + hash_mac.len();
//             if hash_mac != &buf[hash_mac_start_offset..hash_mac_end_offset] {
//                 return Err(anyhow::anyhow!("Hash verification failed"));
//             }
//             // aes-256-cbc 解密内容
//             type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
//             let iv = &buf[end - reserve..end - reserve + IV_SIZE];
//             decrypted_buf.extend(
//                 Aes256CbcDec::new(&key.into(), iv.into())
//                     .decrypt_padded_mut::<NoPadding>(&mut buf[start + offset..end - reserve])
//                     .map_err(anyhow::Error::msg)?,
//             );
//             decrypted_buf.extend(&buf[end - reserve..end]);
//         }
//     }
//     Ok(decrypted_buf)
// }

// fn decrypt_db_file_v4(path: &PathBuf, pkey: &String) -> Result<Vec<u8>> {
//     let mut buf = read_file_content(path)?;
//     // 如果开头是 SQLITE_HEADER，说明不需要解密
//     if buf.starts_with(SQLITE_HEADER.as_bytes()) {
//         return Ok(buf);
//     }
//     let mut decrypted_buf: Vec<u8> = vec![];
//     // 获取到文件开头的 salt，用于解密 key
//     let salt = buf[..16].to_owned();
//     // salt 异或 0x3a 得到 mac_salt， 用于计算HMAC
//     let mac_salt: Vec<u8> = salt.to_owned().iter().map(|x| x ^ 0x3a).collect();
//     unsafe {
//         // 通过 pkey 和 salt 迭代 ROUND_COUNT_V4 次解出一个新的 key，用于解密
//         let pass = hex::decode(pkey)?;
//         let key = pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&pass, &salt, ROUND_COUNT_V4);
//         // 通过 key 和 mac_salt 迭代2次解出 mac_key
//         let mac_key = pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&key, &mac_salt, 2);
//         // 开头是 sqlite 头
//         decrypted_buf.extend(SQLITE_HEADER.as_bytes());
//         decrypted_buf.push(0x00);
//         // hash检验码对齐后长度 48，后面校验哈希用
//         let mut reserve = IV_SIZE + HMAC_SHA256_SIZE;
//         reserve = if (reserve % AES_BLOCK_SIZE) == 0 {
//             reserve
//         } else {
//             ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
//         };
//         // 每页大小4096，分别解密
//         let total_page = buf.len() / PAGE_SIZE;
//         for cur_page in 0..total_page {
//             let offset = if cur_page == 0 { SALT_SIZE } else { 0 };
//             let start: usize = cur_page * PAGE_SIZE;
//             let end: usize = start + PAGE_SIZE;
//             // 校验哈希
//             let mut mac = HamcSha512::new_from_slice(&mac_key)?;
//             mac.update(&buf[start + offset..end - reserve + IV_SIZE]);
//             mac.update(std::mem::transmute::<_, &[u8; 4]>(&(cur_page as u32 + 1)).as_ref());
//             let hash_mac = mac.finalize().into_bytes().to_vec();
//             let hash_mac_start_offset = end - reserve + IV_SIZE;
//             let hash_mac_end_offset = hash_mac_start_offset + hash_mac.len();
//             if hash_mac != &buf[hash_mac_start_offset..hash_mac_end_offset] {
//                 return Err(anyhow::anyhow!("Hash verification failed"));
//             }
//             // aes-256-cbc 解密内容
//             type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
//             let iv = &buf[end - reserve..end - reserve + IV_SIZE];
//             decrypted_buf.extend(
//                 Aes256CbcDec::new(&key.into(), iv.into())
//                     .decrypt_padded_mut::<NoPadding>(&mut buf[start + offset..end - reserve])
//                     .map_err(anyhow::Error::msg)?,
//             );
//             decrypted_buf.extend(&buf[end - reserve..end]);
//         }
//     }
//     Ok(decrypted_buf)
// }

fn read_file_content(path: &PathBuf) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    File::open(path)?.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn decrypt_db(path: &PathBuf, pkey: &String, ver: &WechatDbType) -> Result<Vec<u8>> {
    let mut buf = read_file_content(path)?;
    // 如果开头是 SQLITE_HEADER，说明不需要解密
    if buf.starts_with(SQLITE_HEADER.as_bytes()) {
        return Ok(buf);
    }
    let mut decrypted_buf: Vec<u8> = vec![];
    // 获取到文件开头的 salt，用于解密 key
    let salt = buf[..16].to_owned();
    // salt 异或 0x3a 得到 mac_salt， 用于计算HMAC
    let mac_salt: Vec<u8> = salt.to_owned().iter().map(|x| x ^ 0x3a).collect();
    let (round_count, hmac_size) = match ver {
        WechatDbType::V3 => (ROUND_COUNT_V3, HMAC_SHA1_SIZE),
        WechatDbType::V4 => (ROUND_COUNT_V4, HMAC_SHA256_SIZE),
    };

    unsafe {
        // 通过 pkey 和 salt 迭代 round_count 次解出一个新的 key，用于解密
        let pass = hex::decode(pkey)?;
        let key = match ver {
            WechatDbType::V3 => pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&pass, &salt, round_count),
            WechatDbType::V4 => pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&pass, &salt, round_count),
        };
        // 通过 key 和 mac_salt 迭代2次解出 mac_key
        let mac_key = match ver {
            WechatDbType::V3 => pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&key, &mac_salt, 2),
            WechatDbType::V4 => pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&key, &mac_salt, 2),
        };
        // 开头是 sqlite 头
        decrypted_buf.extend(SQLITE_HEADER.as_bytes());
        decrypted_buf.push(0x00);
        // hash检验码对齐后长度 48，后面校验哈希用
        let mut reserve = IV_SIZE + hmac_size;
        reserve = if (reserve % AES_BLOCK_SIZE) == 0 {
            reserve
        } else {
            ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
        };
        // 每页大小4096，分别解密
        let total_page = buf.len() / PAGE_SIZE;
        for cur_page in 0..total_page {
            let offset = if cur_page == 0 { SALT_SIZE } else { 0 };
            let start: usize = cur_page * PAGE_SIZE;
            let end: usize = start + PAGE_SIZE;
            // 校验哈希
            let hash_mac = match ver {
                WechatDbType::V3 => {
                    let mut mac = HamcSha1::new_from_slice(&mac_key)?;
                    mac.update(&buf[start + offset..end - reserve + IV_SIZE]);
                    mac.update(std::mem::transmute::<_, &[u8; 4]>(&(cur_page as u32 + 1)).as_ref());
                    mac.finalize().into_bytes().to_vec()
                }
                WechatDbType::V4 => {
                    let mut mac = HamcSha512::new_from_slice(&mac_key)?;
                    mac.update(&buf[start + offset..end - reserve + IV_SIZE]);
                    mac.update(std::mem::transmute::<_, &[u8; 4]>(&(cur_page as u32 + 1)).as_ref());
                    mac.finalize().into_bytes().to_vec()
                }
            };
            let hash_mac_start_offset = end - reserve + IV_SIZE;
            let hash_mac_end_offset = hash_mac_start_offset + hash_mac.len();
            if hash_mac != &buf[hash_mac_start_offset..hash_mac_end_offset] {
                return Err(anyhow::anyhow!("Hash verification failed"));
            }
            // aes-256-cbc 解密内容
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            let iv = &buf[end - reserve..end - reserve + IV_SIZE];
            decrypted_buf.extend(
                Aes256CbcDec::new(&key.into(), iv.into())
                    .decrypt_padded_mut::<NoPadding>(&mut buf[start + offset..end - reserve])
                    .map_err(anyhow::Error::msg)?,
            );
            decrypted_buf.extend(&buf[end - reserve..end]);
        }
    }
    Ok(decrypted_buf)
}

fn convert_to_sqlcipher_rawkey(pkey: &str, path: &PathBuf, ver: &WechatDbType) -> Result<String> {
    let mut salt = vec![0; SALT_SIZE];
    File::open(path)?.read(salt.as_mut())?;
    let pass = hex::decode(pkey)?;
    match ver {
        WechatDbType::V3 => {
            let key = pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&pass, &salt, ROUND_COUNT_V3);
            let rawkey = [key.as_slice(), &salt].concat();
            Ok(format!("0x{}", hex::encode(rawkey)))
        }
        WechatDbType::V4 => {
            let key = pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&pass, &salt, ROUND_COUNT_V4);
            let rawkey = [key.as_slice(), &salt].concat();
            Ok(format!("0x{}", hex::encode(rawkey)))
        }
    }
}

pub fn execute(args: &Args) {
    let key = args.key.clone();
    let file = args.file.clone();
    let rawkey = args.rawkey.clone();
    let ver: WechatDbType = match args.ver.clone() {
        Some(v) => v,
        None => WechatDbType::V3,
    };
    if rawkey {
        match convert_to_sqlcipher_rawkey(&key, &file, &ver) {
            Ok(r) => println!("{}", r),
            Err(e) => eprintln!("{}", e),
        }
        return;
    }
    match decrypt_db(&file, &key, &ver) {
        Ok(r) => {
            let path = file.with_extension("decrypted.db");
            fs::write(path.clone(), r).unwrap();
            println!("Decrypted file: {:?}", path);
        }
        Err(e) => eprintln!("{}", e),
    }
}
