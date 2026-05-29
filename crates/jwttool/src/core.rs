//! JWT core functions

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use colored_json::to_colored_json_auto;
use hmac::{Hmac, Mac};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde_json::{json, Value};
use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// Print JWT token in pretty format
pub fn jwt_print(token: &str, _secret: &str) -> Result<String> {
    let token = token.trim();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid JWT format"));
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let header: Value = serde_json::from_slice(&header_bytes)?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let payload: Value = serde_json::from_slice(&payload_bytes)?;

    let result = json!({
        "header": header,
        "payload": payload,
        "signature": parts.get(2).unwrap_or(&""),
    });

    Ok(to_colored_json_auto(&result)?)
}

/// Modify JWT token
pub fn jwt_modify(
    token: &str,
    none: bool,
    secret: &str,
    headers: &HashMap<String, String>,
    claims: &HashMap<String, String>,
    method: &str,
    is_print: bool,
) -> Result<String> {
    let token = token.trim();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid JWT format"));
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let mut header: Value = serde_json::from_slice(&header_bytes)?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let mut payload: Value = serde_json::from_slice(&payload_bytes)?;

    // Modify headers
    if let Value::Object(ref mut map) = header {
        for (k, v) in headers {
            map.insert(k.clone(), Value::String(v.clone()));
        }
    }

    // Modify claims
    if let Value::Object(ref mut map) = payload {
        for (k, v) in claims {
            map.insert(k.clone(), Value::String(v.clone()));
        }
    }

    if none {
        // Set algorithm to none
        if let Value::Object(ref mut map) = header {
            map.insert("alg".to_string(), Value::String("none".to_string()));
        }

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?);
        return Ok(format!("{header_b64}.{payload_b64}."));
    }

    // Determine method
    let alg = if method.is_empty() {
        header["alg"].as_str().unwrap_or("HS256").to_string()
    } else {
        method.to_string()
    };

    // Update algorithm in header
    if let Value::Object(ref mut map) = header {
        map.insert("alg".to_string(), Value::String(alg.clone()));
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = sign(&signing_input, secret, &alg)?;
    let token_string = format!("{signing_input}.{signature}");

    if is_print {
        if let Ok(printed) = jwt_print(&token_string, secret) {
            eprintln!("{printed}");
        }
    }

    Ok(token_string)
}

/// Create a new JWT token
pub fn jwt_create(claims: &HashMap<String, String>, method: &str, secret: &str) -> Result<String> {
    let header = json!({
        "alg": method,
        "typ": "JWT"
    });

    let mut payload = serde_json::Map::new();
    for (k, v) in claims {
        payload.insert(k.clone(), Value::String(v.clone()));
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&Value::Object(payload))?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = sign(&signing_input, secret, method)?;

    Ok(format!("{signing_input}.{signature}"))
}

/// Sign the input with HMAC
fn sign(input: &str, secret: &str, method: &str) -> Result<String> {
    let secret_bytes = secret.as_bytes();
    let input_bytes = input.as_bytes();

    let signature = match method {
        "HS256" => {
            let mut mac = HmacSha256::new_from_slice(secret_bytes)
                .map_err(|e| anyhow!("Invalid key: {}", e))?;
            mac.update(input_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        "HS384" => {
            let mut mac = HmacSha384::new_from_slice(secret_bytes)
                .map_err(|e| anyhow!("Invalid key: {}", e))?;
            mac.update(input_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = HmacSha512::new_from_slice(secret_bytes)
                .map_err(|e| anyhow!("Invalid key: {}", e))?;
            mac.update(input_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        _ => return Err(anyhow!("Unsupported method: {}", method)),
    };

    Ok(URL_SAFE_NO_PAD.encode(signature))
}

/// Verify JWT token with secret
#[allow(dead_code)]
fn verify(token: &str, secret: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let header_bytes = match URL_SAFE_NO_PAD.decode(parts[0]) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let header: Value = match serde_json::from_slice(&header_bytes) {
        Ok(h) => h,
        Err(_) => return false,
    };

    let alg = match header["alg"].as_str() {
        Some(a) => a,
        None => return false,
    };

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected_sig = match sign(&signing_input, secret, alg) {
        Ok(s) => s,
        Err(_) => return false,
    };

    expected_sig == parts[2]
}

/// Pre-parsed JWT token for fast verification
#[derive(Clone)]
struct ParsedToken {
    signing_input: String,
    expected_signature: String,
    algorithm: String,
}

impl ParsedToken {
    fn parse(token: &str) -> Option<Self> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
        let header: Value = serde_json::from_slice(&header_bytes).ok()?;
        let algorithm = header["alg"].as_str()?.to_string();

        Some(Self {
            signing_input: format!("{}.{}", parts[0], parts[1]),
            expected_signature: parts[2].to_string(),
            algorithm,
        })
    }

    /// Fast verify with pre-parsed token info
    fn verify(&self, secret: &str) -> bool {
        let expected_sig = match sign(&self.signing_input, secret, &self.algorithm) {
            Ok(s) => s,
            Err(_) => return false,
        };
        expected_sig == self.expected_signature
    }
}

/// Generate all combinations of given length
fn generate_combinations(alphabet: &[char], length: usize) -> Vec<Vec<char>> {
    if length == 0 {
        return vec![vec![]];
    }
    if length == 1 {
        return alphabet.iter().map(|&c| vec![c]).collect();
    }

    let mut result = Vec::new();
    let sub_combinations = generate_combinations(alphabet, length - 1);

    for &c in alphabet {
        for sub in &sub_combinations {
            let mut combo = vec![c];
            combo.extend(sub);
            result.push(combo);
        }
    }
    result
}

/// Crack JWT secret using brute force with optimized parallelism and progress tracking
pub fn jwt_crack(
    token: &str,
    min_len: usize,
    max_len: usize,
    alphabet: &str,
    prefix: &str,
    suffix: &str,
) -> Result<String> {
    let token = token.trim();
    let parsed_token =
        ParsedToken::parse(token).ok_or_else(|| anyhow!("Invalid JWT token format"))?;

    let alphabet_chars: Vec<char> = alphabet.chars().collect();
    let found = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));

    // Calculate total combinations
    let prefix_suffix_len = prefix.len() + suffix.len();
    let effective_min = min_len.saturating_sub(prefix_suffix_len).max(1);
    let effective_max = max_len.saturating_sub(prefix_suffix_len);

    let total: u64 = (effective_min..=effective_max)
        .map(|len| (alphabet_chars.len() as u64).pow(len as u32))
        .sum();

    // Setup progress bar
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | {per_sec} | ETA: {eta}")
            .unwrap()
            .progress_chars("█▓▒░"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let start_time = std::time::Instant::now();
    let mut result: Option<String> = None;

    // Process each length sequentially, but parallelize within each length
    for current_len in effective_min..=effective_max {
        if found.load(Ordering::Relaxed) {
            break;
        }

        // Generate work batches for this length
        // For small alphabet or length, generate all combinations directly
        // For large ones, divide work by first character(s)
        let batch_depth = if alphabet_chars.len() <= 26 && current_len <= 3 {
            current_len // Process all at once
        } else {
            2.min(current_len) // Split by first 2 chars for parallelism
        };

        let prefixes = generate_combinations(&alphabet_chars, batch_depth);
        let remaining_len = current_len - batch_depth;

        let found_secret: Option<String> = prefixes.par_iter().find_map_any(|batch_prefix| {
            if found.load(Ordering::Relaxed) {
                return None;
            }

            let batch_prefix_str: String = batch_prefix.iter().collect();

            // Generate remaining combinations for this prefix
            let suffixes = if remaining_len > 0 {
                generate_combinations(&alphabet_chars, remaining_len)
            } else {
                vec![vec![]]
            };

            for suffix_chars in &suffixes {
                if found.load(Ordering::Relaxed) {
                    return None;
                }

                let core: String = if suffix_chars.is_empty() {
                    batch_prefix_str.clone()
                } else {
                    format!(
                        "{}{}",
                        batch_prefix_str,
                        suffix_chars.iter().collect::<String>()
                    )
                };

                let secret = format!("{prefix}{core}{suffix}");

                // Update progress
                let count = counter.fetch_add(1, Ordering::Relaxed);
                if count.is_multiple_of(10000) {
                    pb.set_position(count);
                }

                if parsed_token.verify(&secret) {
                    found.store(true, Ordering::Relaxed);
                    return Some(secret);
                }
            }

            None
        });

        if let Some(secret) = found_secret {
            result = Some(secret);
            break;
        }
    }

    let elapsed = start_time.elapsed();
    let total_tried = counter.load(Ordering::Relaxed);

    pb.finish_and_clear();

    // Print statistics
    eprintln!(
        "Cracked {} keys in {:.2}s ({:.0} keys/sec)",
        total_tried,
        elapsed.as_secs_f64(),
        total_tried as f64 / elapsed.as_secs_f64()
    );

    match result {
        Some(secret) => {
            eprintln!("JWT Secret Found: {secret}");
            Ok(secret)
        }
        None => Err(anyhow!("Crack failed: secret not found")),
    }
}
