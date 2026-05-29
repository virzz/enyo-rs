use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const DS_STORE_FILE: &str = ".DS_Store";

/// 简单解析 .DS_Store 文件
/// DS_Store 文件格式比较复杂，这里使用简化的方式提取文件名
fn parse_ds_store_data(data: &[u8]) -> Result<Vec<String>> {
    let mut files: HashSet<String> = HashSet::new();

    // DS_Store 文件中的文件名通常是 UTF-16 BE 编码
    // 简化处理：查找可打印 ASCII 字符序列
    let mut i = 0;
    while i < data.len() {
        // 查找连续的可打印字符
        let mut name = String::new();
        let mut j = i;

        // 检查是否是 UTF-16 BE 编码的字符串 (每两个字节一个字符，第一个字节为 0)
        while j + 1 < data.len() {
            if data[j] == 0 && data[j + 1] >= 0x20 && data[j + 1] <= 0x7E {
                name.push(data[j + 1] as char);
                j += 2;
            } else if data[j] >= 0x20 && data[j] <= 0x7E && data[j + 1] == 0 {
                // UTF-16 LE
                name.push(data[j] as char);
                j += 2;
            } else {
                break;
            }
        }

        // 如果找到有效的文件名（长度 >= 2 且不包含特殊模式）
        if name.len() >= 2
            && !name.contains("Bud1")
            && !name.contains("DSDB")
            && !name.starts_with(".")
            && !name.contains('\0')
        {
            // 过滤掉一些常见的元数据字段
            let skip_patterns = [
                "Iloc", "bwsp", "lsvp", "lsvP", "icvp", "vSrn", "BKGD", "ICVO", "dilc", "dscl",
                "fdsc", "fwi0", "fwsw", "fwvh", "glvp", "GRP0", "icgo", "icsp", "icv4", "icvo",
                "info", "logS", "lg1S", "lssp", "lsvC", "lsvo", "moDD", "modD", "ph1S", "pict",
                "vstl", "ptbL", "ptbN",
            ];

            let should_skip = skip_patterns.iter().any(|p| name.contains(p));
            if !should_skip && name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                files.insert(name);
            }
        }

        i = if j > i { j } else { i + 1 };
    }

    let mut result: Vec<String> = files.into_iter().map(|f| format!("- {f}")).collect();
    result.sort();
    Ok(result)
}

/// 解析 .DS_Store 文件或 URL
pub async fn parse_ds_store(src: &str) -> Result<String> {
    // URL 解析
    if src.starts_with("http") {
        let url = if src.ends_with(DS_STORE_FILE) {
            src.to_string()
        } else {
            format!("{}/{}", src.trim_end_matches('/'), DS_STORE_FILE)
        };

        let client = reqwest::Client::new();
        let response = client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch {}: {}", url, response.status()));
        }

        let data = response.bytes().await?;
        let files = parse_ds_store_data(&data)?;

        let base_url = url.trim_end_matches(DS_STORE_FILE).trim_end_matches('/');
        let result: Vec<String> = files
            .iter()
            .map(|f| format!("{}/{}", base_url, f.trim_start_matches("- ")))
            .collect();

        return Ok(result.join("\n"));
    }

    // 本地文件解析
    let path = if src.ends_with(DS_STORE_FILE) {
        src.to_string()
    } else {
        Path::new(src)
            .join(DS_STORE_FILE)
            .to_string_lossy()
            .to_string()
    };

    if !Path::new(&path).exists() {
        return Err(anyhow!("File not found: {}", path));
    }

    let data = fs::read(&path)?;
    let files = parse_ds_store_data(&data)?;
    Ok(files.join("\n"))
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_parse_ds_store_local() {
        // 需要实际的 .DS_Store 文件进行测试
    }
}
