use axum::http::{header, HeaderMap, HeaderValue};

use super::config::Provider;

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

pub fn apply_api_key(
    headers: &mut HeaderMap,
    provider: Provider,
    configured: Option<&str>,
    extracted: Option<&str>,
) {
    let Some(key) = configured.or(extracted) else {
        return;
    };

    match provider {
        Provider::OpenAiChat | Provider::OpenAiResponses => {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {key}")) {
                headers.insert(header::AUTHORIZATION, value);
            }
        }
        Provider::Anthropic => {
            if let Ok(value) = HeaderValue::from_str(key) {
                headers.insert("x-api-key", value);
            }
        }
    }
}

pub fn apply_protocol_headers(headers: &mut HeaderMap, provider: Provider, source: &HeaderMap) {
    if provider != Provider::Anthropic {
        return;
    }
    for name in ["anthropic-version", "anthropic-beta"] {
        if let Some(value) = source.get(name) {
            headers.insert(name, value.clone());
        }
    }
    if !headers.contains_key("anthropic-version") {
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
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

        apply_api_key(
            &mut headers,
            Provider::OpenAiChat,
            Some("sk-config"),
            Some("sk-client"),
        );

        assert_eq!(
            headers
                .get(header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer sk-config"
        );
    }

    #[test]
    fn applies_anthropic_key_and_version_headers() {
        let source = HeaderMap::new();
        let mut headers = HeaderMap::new();

        apply_api_key(&mut headers, Provider::Anthropic, Some("sk-ant"), None);
        apply_protocol_headers(&mut headers, Provider::Anthropic, &source);

        assert_eq!(headers["x-api-key"], "sk-ant");
        assert_eq!(headers["anthropic-version"], "2023-06-01");
        assert!(!headers.contains_key(header::AUTHORIZATION));
    }
}
