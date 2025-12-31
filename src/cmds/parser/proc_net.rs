use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fs;

// TCP 状态映射
lazy_static::lazy_static! {
    static ref TCP_STATE: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("01", "ESTABLISHED");
        m.insert("02", "SYN-SENT");
        m.insert("03", "SYN-RECEIVED");
        m.insert("04", "FIN-WAIT-1");
        m.insert("05", "FIN-WAIT-2");
        m.insert("06", "TIME-WAIT");
        m.insert("07", "CLOSED");
        m.insert("08", "CLOSE-WAIT");
        m.insert("09", "LAST-ACK");
        m.insert("0A", "LISTEN");
        m.insert("0B", "CLOSING");
        m.insert("0C", "NEW-SYN-RECEIVED");
        m
    };
}

#[derive(Debug)]
struct ProcNetTcp {
    local_ip: String,
    local_port: String,
    remote_ip: String,
    remote_port: String,
    state: String,
}

/// 十六进制转 IP 地址 (小端序)
fn hex_to_ip(hex_str: &str) -> String {
    if hex_str.len() != 8 {
        return String::new();
    }
    let bytes: Vec<u8> = (0..4)
        .filter_map(|i| u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok())
        .collect();
    if bytes.len() != 4 {
        return String::new();
    }
    // 小端序转换
    format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
}

/// 十六进制转端口号
fn hex_to_port(hex_str: &str) -> String {
    u16::from_str_radix(hex_str, 16)
        .map(|p| p.to_string())
        .unwrap_or_default()
}

/// 解析 /proc/net/tcp|udp 内容
pub fn parse_proc_net(src: &str) -> Result<String> {
    let data_str = if src.contains("local_address") {
        // 直接是内容
        src.to_string()
    } else if src.starts_with("http") {
        // URL - 暂不支持
        return Err(anyhow!("URL parsing not supported in this version"));
    } else if let Ok(content) = fs::read_to_string(src) {
        // 文件路径
        content
    } else {
        // 当作内容处理
        src.to_string()
    };

    let mut results = Vec::new();
    let re = Regex::new(r"(?m)(\d:) ([0-9a-fA-F]+):([0-9a-fA-F]+) ([0-9a-fA-F]+):([0-9a-fA-F]+) ([0-9a-fA-F]+)")?;

    for cap in re.captures_iter(&data_str) {
        let state_code = cap.get(6).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
        let state = TCP_STATE.get(state_code.as_str()).unwrap_or(&"").to_string();

        results.push(ProcNetTcp {
            local_ip: hex_to_ip(cap.get(2).map(|m| m.as_str()).unwrap_or("")),
            local_port: hex_to_port(cap.get(3).map(|m| m.as_str()).unwrap_or("")),
            remote_ip: hex_to_ip(cap.get(4).map(|m| m.as_str()).unwrap_or("")),
            remote_port: hex_to_port(cap.get(5).map(|m| m.as_str()).unwrap_or("")),
            state,
        });
    }

    // 格式化输出为表格
    let mut output = String::new();
    output.push_str(&format!(
        "{:<25} {:<25} {:<20}\n",
        "Local", "Remote", "State"
    ));
    output.push_str(&"-".repeat(70));
    output.push('\n');

    for r in &results {
        output.push_str(&format!(
            "{:<25} {:<25} {:<20}\n",
            format!("{}:{}", r.local_ip, r.local_port),
            format!("{}:{}", r.remote_ip, r.remote_port),
            r.state
        ));
    }

    output.push_str(&"-".repeat(70));
    output.push('\n');
    output.push_str(&format!("Connections - Total: {}", results.len()));

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_ip() {
        assert_eq!(hex_to_ip("0100007F"), "127.0.0.1");
        assert_eq!(hex_to_ip("00000000"), "0.0.0.0");
    }

    #[test]
    fn test_hex_to_port() {
        assert_eq!(hex_to_port("0050"), "80");
        assert_eq!(hex_to_port("01BB"), "443");
        assert_eq!(hex_to_port("1F90"), "8080");
    }

    #[test]
    fn test_parse_proc_net() {
        let sample = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0"#;
        
        let result = parse_proc_net(sample).unwrap();
        println!("{result}");
        assert!(result.contains("127.0.0.1"));
    }
}

