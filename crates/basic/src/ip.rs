use std::{net::Ipv4Addr, str::FromStr};

use anyhow::{anyhow, Result};
use serde::Serialize;

#[derive(Serialize)]
struct IpReport {
    ip: String,
    hex: String,
    dec: String,
    oct: String,
}

pub fn format_ip_values(values: &[String]) -> Result<String> {
    let reports = ip_reports(values)?;
    Ok(format_reports_text(&reports))
}

pub fn format_ip_values_json(values: &[String]) -> Result<String> {
    let reports = ip_reports(values)?;
    Ok(serde_json::to_string(&reports)?)
}

pub fn format_ipv4_values(values: &[String]) -> Result<String> {
    let reports = ipv4_reports(values)?;
    Ok(format_reports_text(&reports))
}

pub fn format_ipv4_values_json(values: &[String]) -> Result<String> {
    let reports = ipv4_reports(values)?;
    Ok(serde_json::to_string(&reports)?)
}

pub fn format_any_ips(values: &[String]) -> Result<String> {
    Ok(any_ips(values).join("\n"))
}

pub fn format_any_ips_json(values: &[String]) -> Result<String> {
    Ok(serde_json::to_string(&any_ips(values))?)
}

fn ip_reports(values: &[String]) -> Result<Vec<IpReport>> {
    if values.is_empty() {
        return Err(anyhow!("IP requires at least 1 value"));
    }

    values
        .iter()
        .map(|value| parse_any(value).map(report_from_u32))
        .collect()
}

fn ipv4_reports(values: &[String]) -> Result<Vec<IpReport>> {
    if values.is_empty() {
        return Err(anyhow!("IP requires at least 1 value"));
    }

    values
        .iter()
        .map(|value| ipv4_to_u32(value).map(report_from_u32))
        .collect()
}

fn any_ips(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| parse_any(value).ok().map(u32_to_ip))
        .collect()
}

fn format_reports_text(reports: &[IpReport]) -> String {
    reports
        .iter()
        .map(|report| {
            format!(
                "IP: {}\nHex: {}\nDec: {}\nOct: {}\n",
                report.ip, report.hex, report.dec, report.oct
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn ip_to_hex(value: &str) -> Result<String> {
    Ok(format!("0x{:08x}", ipv4_to_u32(value)?))
}

pub fn hex_to_ip(value: &str) -> Result<String> {
    Ok(u32_to_ip(parse_hex(value)?))
}

pub fn ip_to_dec(value: &str) -> Result<String> {
    Ok(ipv4_to_u32(value)?.to_string())
}

pub fn dec_to_ip(value: &str) -> Result<String> {
    Ok(u32_to_ip(parse_dec(value)?))
}

pub fn ip_to_oct(value: &str) -> Result<String> {
    let addr = Ipv4Addr::from_str(value.trim()).map_err(|_| anyhow!("Invalid IPv4 address"))?;
    let octets = addr.octets();
    Ok(format!(
        "{}.{}.{}.{}",
        format_octet_octal(octets[0]),
        format_octet_octal(octets[1]),
        format_octet_octal(octets[2]),
        format_octet_octal(octets[3])
    ))
}

pub fn oct_to_ip(value: &str) -> Result<String> {
    Ok(u32_to_ip(parse_oct(value)?))
}

fn parse_any(value: &str) -> Result<u32> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("Invalid IP value"));
    }

    if is_oct(value) {
        return parse_oct(value);
    }
    if value.starts_with("0x") || value.starts_with("0X") || is_plain_hex_ip(value) {
        return parse_hex(value);
    }
    if value.contains('.') {
        return ipv4_to_u32(value);
    }
    parse_dec(value)
}

fn report_from_u32(value: u32) -> IpReport {
    let ip = u32_to_ip(value);
    IpReport {
        hex: format!("0x{value:08x}"),
        dec: value.to_string(),
        oct: ip_to_oct(&ip).expect("u32 formatted as IPv4 must be valid"),
        ip,
    }
}

fn ipv4_to_u32(value: &str) -> Result<u32> {
    let addr = Ipv4Addr::from_str(value.trim()).map_err(|_| anyhow!("Invalid IPv4 address"))?;
    Ok(u32::from(addr))
}

fn u32_to_ip(value: u32) -> String {
    Ipv4Addr::from(value).to_string()
}

fn parse_hex(value: &str) -> Result<u32> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim());
    if value.is_empty() || value.len() > 8 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Invalid hex IP"));
    }
    u32::from_str_radix(value, 16).map_err(|_| anyhow!("Invalid hex IP"))
}

fn parse_dec(value: &str) -> Result<u32> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| anyhow!("Invalid decimal IP"))
}

fn parse_oct(value: &str) -> Result<u32> {
    let parts = value.trim().split('.').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(anyhow!("Invalid octal IP"));
    }

    let mut octets = [0u8; 4];
    for (idx, part) in parts.iter().enumerate() {
        let raw = part.strip_prefix('0').unwrap_or(part);
        let byte = u8::from_str_radix(if raw.is_empty() { "0" } else { raw }, 8)
            .map_err(|_| anyhow!("Invalid octal IP"))?;
        octets[idx] = byte;
    }
    Ok(u32::from(Ipv4Addr::from(octets)))
}

fn is_oct(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| matches!(c, '0'..='7')))
        && parts
            .iter()
            .any(|part| part.len() > 1 && part.starts_with('0'))
}

fn is_plain_hex_ip(value: &str) -> bool {
    value.len() == 8
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && value.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F'))
}

fn format_octet_octal(value: u8) -> String {
    let value = format!("{value:o}");
    if value.len() == 3 {
        format!("0{value}")
    } else {
        format!("{value:0>3}")
    }
}
