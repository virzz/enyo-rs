use axum::http::{header, HeaderMap, HeaderValue};

pub fn extract_api_key(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = value.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }

    for name in ["x-api-key", "api-key"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            return Some(value.to_string());
        }
    }

    query.and_then(extract_query_key)
}

pub fn apply_api_key(headers: &mut HeaderMap, configured: Option<&str>, extracted: Option<&str>) {
    let Some(key) = configured.or(extracted) else {
        return;
    };

    if let Ok(value) = HeaderValue::from_str(&format!("Bearer {key}")) {
        headers.insert(header::AUTHORIZATION, value);
    }
}

fn extract_query_key(query: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "key")
        .map(|(_, value)| value.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_before_other_keys() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-bearer"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("sk-x"));

        assert_eq!(
            extract_api_key(&headers, None).as_deref(),
            Some("sk-bearer")
        );
    }

    #[test]
    fn extracts_query_key_last() {
        let headers = HeaderMap::new();

        assert_eq!(
            extract_api_key(&headers, Some("alt=sse&key=sk-query")).as_deref(),
            Some("sk-query")
        );
    }

    #[test]
    fn configured_key_overrides_extracted_key() {
        let mut headers = HeaderMap::new();

        apply_api_key(&mut headers, Some("sk-config"), Some("sk-client"));

        assert_eq!(
            headers
                .get(header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer sk-config"
        );
    }
}
