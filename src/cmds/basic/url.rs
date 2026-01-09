use anyhow::Result;

/// URL Encode
pub fn url_encode(s: &str, raw: bool) -> Result<String> {
    let encoded: String = url::form_urlencoded::byte_serialize(s.as_bytes()).collect();
    if raw {
        Ok(encoded.replace('+', "%20"))
    } else {
        Ok(encoded)
    }
}

/// URL Decode
pub fn url_decode(s: &str) -> Result<String> {
    let decoded = url::form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| {
            if v.is_empty() {
                k.to_string()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");

    // 如果输入不包含 = 号，直接解码
    if !s.contains('=') {
        Ok(urlencoding::decode(s)?.into_owned())
    } else {
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        let input = "argver\t\t\\=!@#$%^&* abc def";
        let result = url_encode(input, true).unwrap();
        println!("URL Encode (raw): {result}");
        assert!(result.contains("%20")); // 空格应该被编码为 %20 而不是 +
    }

    #[test]
    fn test_url_encode_normal() {
        let input = "hello world";
        let result = url_encode(input, false).unwrap();
        println!("URL Encode: {result}");
        assert_eq!(result, "hello+world");
    }

    #[test]
    fn test_url_decode() {
        let input = "argver%09%09%5C%3D%21%40%23%24%25%5E%26%2A";
        let result = url_decode(input).unwrap();
        println!("URL Decode: {result}");
    }

    #[test]
    fn test_url_decode_space() {
        let input = "hello%20world";
        let result = url_decode(input).unwrap();
        assert_eq!(result, "hello world");
    }
}
