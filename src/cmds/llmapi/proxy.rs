use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;

use super::{
    adapters::{
        anthropic::AnthropicAdapter, gemini::GeminiAdapter, openai_chat::OpenAiChatAdapter,
        openai_responses::OpenAiResponsesAdapter, AdapterError, RequestAdapter, ResponseAdapter,
        StreamAdapter,
    },
    auth,
    log::{self, LogEvent},
    model::{LLMRequest, LLMResponse},
    protocol::{detect_input, is_transparent, upstream_for, InputFormat, UpstreamFormat},
    server::AppState,
};

struct ForwardRequest<'a> {
    state: AppState,
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
    let Some(input) = detect_input(request.uri().path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (upstream, path) = upstream_for(state.config.provider, &input);
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

    if is_transparent(&input, &upstream) {
        let path = transparent_path(&input, &path);
        log::emit(LogEvent::TransparentProxyUsed, &path);
        return forward_raw(state, &headers, query.as_deref(), &path, body).await;
    }

    log::emit(LogEvent::AdapterUsed, format!("{input:?} -> {upstream:?}"));
    convert_and_forward(ForwardRequest {
        state,
        headers: &headers,
        query: query.as_deref(),
        input: &input,
        upstream,
        path: &path,
        body,
        upstream_raw,
    })
    .await
}

pub async fn forward_raw(
    state: AppState,
    headers: &HeaderMap,
    query: Option<&str>,
    path: &str,
    body: Bytes,
) -> Response<Body> {
    let url = format!("{}{}", state.config.base_url, path);
    let result = send_upstream_request(state, headers, query, &url, body).await;

    match result {
        Ok(upstream) => {
            log::emit(
                LogEvent::UpstreamResponseReceived,
                format!(
                    "POST {} {}",
                    log::redact_url(upstream.url().as_str()),
                    upstream.status()
                ),
            );
            raw_upstream_response(upstream)
        }
        Err(err) => {
            log::emit(LogEvent::UpstreamError, err.to_string());
            response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            )
        }
    }
}

async fn send_upstream_request(
    state: AppState,
    headers: &HeaderMap,
    query: Option<&str>,
    url: &str,
    body: Bytes,
) -> Result<reqwest::Response, reqwest::Error> {
    let extracted = auth::extract_api_key(headers, query);
    let mut upstream_headers = HeaderMap::new();
    auth::apply_api_key(
        &mut upstream_headers,
        state.config.api_key.as_deref(),
        extracted.as_deref(),
    );
    state
        .client
        .post(url)
        .headers(upstream_headers)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
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

    let path = materialize_path_for_request(forward.path, forward.upstream, &llm_request);
    let url = format!("{}{}", forward.state.config.base_url, path);
    let upstream_response = match send_upstream_request(
        forward.state.clone(),
        forward.headers,
        forward.query,
        &url,
        Bytes::from(serde_json::to_vec(&upstream_json).unwrap()),
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            log::emit(LogEvent::UpstreamError, err.to_string());
            return response(
                StatusCode::BAD_GATEWAY,
                Bytes::from(err.to_string()),
                "text/plain",
            );
        }
    };
    log::emit(
        LogEvent::UpstreamResponseReceived,
        format!(
            "POST {} {}",
            log::redact_url(upstream_response.url().as_str()),
            upstream_response.status()
        ),
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
        InputFormat::GeminiGenerate { model, stream } => {
            GeminiAdapter::to_llm_request_with_model(value, model, *stream)
        }
    }
}

fn llm_to_upstream(upstream: UpstreamFormat, request: &LLMRequest) -> Result<Value, AdapterError> {
    match upstream {
        UpstreamFormat::OpenAiChat => OpenAiChatAdapter::from_llm_request(request),
        UpstreamFormat::OpenAiResponses => OpenAiResponsesAdapter::from_llm_request(request),
        UpstreamFormat::AnthropicMessages => AnthropicAdapter::from_llm_request(request),
        UpstreamFormat::GeminiGenerate => GeminiAdapter::from_llm_request(request),
    }
}

fn materialize_path(path: &str, model: &str) -> String {
    path.replace("{model}", model)
}

fn materialize_path_for_request(
    path: &str,
    upstream: UpstreamFormat,
    request: &LLMRequest,
) -> String {
    let path = materialize_path(path, &request.model);
    if upstream == UpstreamFormat::GeminiGenerate && request.stream {
        path.replace(":generateContent", ":streamGenerateContent")
    } else {
        path
    }
}

fn transparent_path(input: &InputFormat, path: &str) -> String {
    match input {
        InputFormat::GeminiGenerate { model, stream } => {
            let action = if *stream {
                "streamGenerateContent"
            } else {
                "generateContent"
            };
            format!("/v1beta/models/{model}:{action}")
        }
        _ => path.to_string(),
    }
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
        return converted_sse_response(upstream_response, input.clone(), upstream);
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
        UpstreamFormat::GeminiGenerate => GeminiAdapter::to_llm_response(value),
    }
}

fn llm_to_input(input: &InputFormat, response: &LLMResponse) -> Result<Value, AdapterError> {
    match input {
        InputFormat::OpenAiChat => OpenAiChatAdapter::from_llm_response(response),
        InputFormat::OpenAiResponses => OpenAiResponsesAdapter::from_llm_response(response),
        InputFormat::AnthropicMessages => AnthropicAdapter::from_llm_response(response),
        InputFormat::GeminiGenerate { .. } => GeminiAdapter::from_llm_response(response),
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
        UpstreamFormat::GeminiGenerate => GeminiAdapter::parse_stream_event(event),
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
        InputFormat::GeminiGenerate { .. } => GeminiAdapter::format_stream_event(event),
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
                log::emit(LogEvent::StreamEventConversionWarning, err.to_string());
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            log::emit(LogEvent::StreamEventConversionWarning, err.to_string());
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
