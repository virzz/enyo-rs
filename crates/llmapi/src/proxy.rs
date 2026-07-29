use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Method, Response, StatusCode},
};
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use serde_json::Value;
use tracing::{debug, error, info, warn};

use super::{
    adapters::{
        anthropic::AnthropicAdapter, openai_chat::OpenAiChatAdapter,
        openai_responses::OpenAiResponsesAdapter, AdapterError, RequestAdapter, ResponseAdapter,
        StreamAdapter,
    },
    auth,
    config::ProviderConfig,
    model::{LLMRequest, LLMResponse},
    protocol::{detect_route, is_transparent, upstream_for, InputFormat, UpstreamFormat},
    redact,
    server::AppState,
};

struct ForwardRequest<'a> {
    state: AppState,
    provider: ProviderConfig,
    headers: &'a HeaderMap,
    query: Option<&'a str>,
    input: &'a InputFormat,
    upstream: UpstreamFormat,
    path: &'a str,
    body: Bytes,
    upstream_raw: bool,
}

pub async fn handle(
    state: AppState,
    headers: HeaderMap,
    request: axum::http::Request<Body>,
) -> Response<Body> {
    let upstream_raw = wants_upstream_raw(request.uri(), &headers);
    let query = request.uri().query().map(ToString::to_string);
    let method = request.method().clone();
    let request_path = request.uri().path().to_string();
    let Some(route) = detect_route(&request_path) else {
        return response(
            StatusCode::NOT_FOUND,
            Bytes::from("unknown llmapi route"),
            "text/plain",
        );
    };
    if method != Method::POST {
        return response(
            StatusCode::METHOD_NOT_ALLOWED,
            Bytes::from("llmapi endpoints require POST"),
            "text/plain",
        );
    }
    let mut provider = match state.config.provider(route.provider.as_deref()) {
        Ok((_, provider)) => provider.clone(),
        Err(err) => {
            return response(
                StatusCode::NOT_FOUND,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    provider.api_key = match provider.api_key() {
        Ok(api_key) => api_key,
        Err(err) => {
            return response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    let body = match to_bytes(request.into_body(), usize::MAX).await {
        Ok(body) => body,
        Err(err) => {
            return response(
                StatusCode::BAD_REQUEST,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    let input = route.input;
    let (upstream, path) = upstream_for(provider.provider_type);

    if is_transparent(input, upstream) {
        debug!(target: "llmapi", path, "transparent proxy");
        return forward_raw(
            state,
            provider,
            &headers,
            method,
            query.as_deref(),
            path,
            body,
        )
        .await;
    }

    debug!(target: "llmapi", ?input, ?upstream, "protocol adapter selected");
    convert_and_forward(ForwardRequest {
        state,
        provider,
        headers: &headers,
        query: query.as_deref(),
        input: &input,
        upstream,
        path,
        body,
        upstream_raw,
    })
    .await
}

pub fn forward_raw(
    state: AppState,
    provider: ProviderConfig,
    headers: &HeaderMap,
    method: Method,
    query: Option<&str>,
    path: &str,
    body: Bytes,
) -> impl std::future::Future<Output = Response<Body>> + Send {
    let url = upstream_url(&provider.base_url, path, query);
    let upstream_method = method.as_str().to_string();
    send_upstream_request(state, provider, headers, method, query, &url, body).map(move |result| {
        match result {
            Ok(upstream) => {
                info!(
                    target: "llmapi",
                    method = %upstream_method,
                    url = %redact::url(upstream.url().as_str()),
                    status = %upstream.status(),
                    "upstream response received"
                );
                raw_upstream_response(upstream)
            }
            Err(err) => {
                error!(target: "llmapi", error = %err, "upstream request failed");
                response(
                    StatusCode::BAD_GATEWAY,
                    Bytes::from(err.to_string()),
                    "text/plain",
                )
            }
        }
    })
}

fn send_upstream_request(
    state: AppState,
    provider: ProviderConfig,
    headers: &HeaderMap,
    method: Method,
    auth_query: Option<&str>,
    url: &str,
    body: Bytes,
) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> + Send {
    let extracted = auth::extract_api_key(headers, auth_query);
    let mut upstream_headers = HeaderMap::new();
    auth::apply_api_key(
        &mut upstream_headers,
        provider.provider_type,
        provider.api_key.as_deref(),
        extracted.as_deref(),
    );
    auth::apply_protocol_headers(&mut upstream_headers, provider.provider_type, headers);
    state
        .client
        .request(method, url)
        .headers(upstream_headers)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
}

pub fn response(status: StatusCode, body: Bytes, content_type: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap()
}

async fn convert_and_forward(forward: ForwardRequest<'_>) -> Response<Body> {
    let input_json: Value = match serde_json::from_slice(&forward.body) {
        Ok(value) => value,
        Err(err) => {
            return response(
                StatusCode::BAD_REQUEST,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    let llm_request = match input_to_llm(forward.input, input_json) {
        Ok(request) => request,
        Err(err) => {
            return response(
                StatusCode::BAD_REQUEST,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    debug!(
        target: "llmapi",
        request = %redact::format_json(&llm_request),
        "normalized LLM request"
    );
    let upstream_json = match llm_to_upstream(forward.upstream, &llm_request) {
        Ok(value) => value,
        Err(err) => {
            return response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };

    let url = upstream_url(&forward.provider.base_url, forward.path, forward.query);
    let upstream_response = match send_upstream_request(
        forward.state.clone(),
        forward.provider,
        forward.headers,
        Method::POST,
        forward.query,
        &url,
        Bytes::from(serde_json::to_vec(&upstream_json).unwrap()),
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            error!(target: "llmapi", error = %err, "upstream request failed");
            return response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    info!(
        target: "llmapi",
        method = "POST",
        url = %redact::url(upstream_response.url().as_str()),
        status = %upstream_response.status(),
        "upstream response received"
    );
    if forward.upstream_raw {
        return raw_upstream_response(upstream_response);
    }
    convert_response_back(upstream_response, forward.input, forward.upstream).await
}

fn input_to_llm(input: &InputFormat, value: Value) -> Result<LLMRequest, AdapterError> {
    match input {
        InputFormat::OpenAiChat => OpenAiChatAdapter::to_llm_request(value),
        InputFormat::OpenAiResponses => OpenAiResponsesAdapter::to_llm_request(value),
        InputFormat::AnthropicMessages => AnthropicAdapter::to_llm_request(value),
    }
}

fn llm_to_upstream(upstream: UpstreamFormat, request: &LLMRequest) -> Result<Value, AdapterError> {
    match upstream {
        UpstreamFormat::OpenAiChat => OpenAiChatAdapter::from_llm_request(request),
        UpstreamFormat::OpenAiResponses => OpenAiResponsesAdapter::from_llm_request(request),
        UpstreamFormat::AnthropicMessages => AnthropicAdapter::from_llm_request(request),
    }
}

fn upstream_url(base_url: &str, path: &str, query: Option<&str>) -> String {
    match query.and_then(forwarded_query) {
        Some(query) => format!("{base_url}{path}?{query}"),
        None => format!("{base_url}{path}"),
    }
}

fn forwarded_query(query: &str) -> Option<String> {
    let values: Vec<_> = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key != "key" && key != "llmapi_response_mode")
        .collect();
    if values.is_empty() {
        return None;
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(values);
    Some(serializer.finish())
}

async fn convert_response_back(
    upstream_response: reqwest::Response,
    input: &InputFormat,
    upstream: UpstreamFormat,
) -> Response<Body> {
    let status = upstream_response.status();
    let content_type = upstream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !status.is_success() {
        return raw_upstream_response(upstream_response);
    }

    if content_type.contains("text/event-stream") {
        return converted_sse_response(upstream_response, *input, upstream);
    }

    let body = upstream_response.bytes().await.unwrap_or_default();
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => {
            return response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    let llm = match upstream_to_llm(upstream, value) {
        Ok(value) => value,
        Err(err) => {
            return response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    debug!(
        target: "llmapi",
        response = %redact::format_json(&llm),
        "normalized LLM response"
    );
    let output = match llm_to_input(input, &llm) {
        Ok(value) => value,
        Err(err) => {
            return response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };

    response(
        StatusCode::OK,
        Bytes::from(serde_json::to_vec(&output).unwrap()),
        "application/json",
    )
}

fn raw_upstream_response(upstream: reqwest::Response) -> Response<Body> {
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap()
}

fn upstream_to_llm(upstream: UpstreamFormat, value: Value) -> Result<LLMResponse, AdapterError> {
    match upstream {
        UpstreamFormat::OpenAiChat => OpenAiChatAdapter::to_llm_response(value),
        UpstreamFormat::OpenAiResponses => OpenAiResponsesAdapter::to_llm_response(value),
        UpstreamFormat::AnthropicMessages => AnthropicAdapter::to_llm_response(value),
    }
}

fn llm_to_input(input: &InputFormat, response: &LLMResponse) -> Result<Value, AdapterError> {
    match input {
        InputFormat::OpenAiChat => OpenAiChatAdapter::from_llm_response(response),
        InputFormat::OpenAiResponses => OpenAiResponsesAdapter::from_llm_response(response),
        InputFormat::AnthropicMessages => AnthropicAdapter::from_llm_response(response),
    }
}

fn parse_stream_event(
    upstream: UpstreamFormat,
    event: &str,
) -> Result<Option<super::model::LLMStreamEvent>, AdapterError> {
    match upstream {
        UpstreamFormat::OpenAiChat => OpenAiChatAdapter::parse_stream_event(event),
        UpstreamFormat::OpenAiResponses => OpenAiResponsesAdapter::parse_stream_event(event),
        UpstreamFormat::AnthropicMessages => AnthropicAdapter::parse_stream_event(event),
    }
}

fn format_stream_event(
    input: &InputFormat,
    event: &super::model::LLMStreamEvent,
) -> Result<Option<String>, AdapterError> {
    match input {
        InputFormat::OpenAiChat => OpenAiChatAdapter::format_stream_event(event),
        InputFormat::OpenAiResponses => OpenAiResponsesAdapter::format_stream_event(event),
        InputFormat::AnthropicMessages => AnthropicAdapter::format_stream_event(event),
    }
}

fn converted_sse_response(
    upstream_response: reqwest::Response,
    input: InputFormat,
    upstream: UpstreamFormat,
) -> Response<Body> {
    let stream = upstream_response.bytes_stream();
    let converted = async_stream::stream! {
        let mut stream = stream;
        let mut buffer = String::new();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    yield Err::<Bytes, std::io::Error>(std::io::Error::other(err));
                    return;
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(index) = buffer.find("\n\n") {
                let event = buffer[..index].trim().to_string();
                buffer.drain(..index + 2);
                if event.is_empty() {
                    continue;
                }
                if let Some(text) = convert_sse_event(&event, &input, upstream) {
                    yield Ok::<Bytes, std::io::Error>(Bytes::from(text));
                }
            }
        }
        let event = buffer.trim();
        if !event.is_empty() {
            if let Some(text) = convert_sse_event(event, &input, upstream) {
                yield Ok::<Bytes, std::io::Error>(Bytes::from(text));
            }
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(converted))
        .unwrap()
}

fn convert_sse_event(event: &str, input: &InputFormat, upstream: UpstreamFormat) -> Option<String> {
    match parse_stream_event(upstream, event) {
        Ok(Some(llm_event)) => match format_stream_event(input, &llm_event) {
            Ok(Some(text)) => Some(text),
            Ok(None) => None,
            Err(err) => {
                warn!(target: "llmapi", error = %err, "stream event conversion failed");
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            warn!(target: "llmapi", error = %err, "stream event conversion failed");
            None
        }
    }
}

fn wants_upstream_raw(uri: &axum::http::Uri, headers: &HeaderMap) -> bool {
    if headers
        .get("x-llmapi-response-mode")
        .and_then(|value| value.to_str().ok())
        == Some("upstream_raw")
    {
        return true;
    }

    uri.query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "llmapi_response_mode" && value == "upstream_raw")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_auth_and_internal_query_parameters_from_upstream_url() {
        assert_eq!(
            upstream_url(
                "https://api.example.test/v1",
                "/responses",
                Some("key=sk-secret&beta=true&llmapi_response_mode=upstream_raw"),
            ),
            "https://api.example.test/v1/responses?beta=true"
        );
    }
}
