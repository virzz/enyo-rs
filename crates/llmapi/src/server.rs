use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, Response, Uri},
    routing::any,
    Router,
};
use tracing::info;

use super::{config::Config, proxy, redact};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub client: reqwest::Client,
}

pub fn app(config: Config) -> Router {
    let state = AppState {
        config: Arc::new(config),
        client: reqwest::Client::new(),
    };

    Router::new()
        .route("/{*path}", any(handler))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr, config: Config) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(target: "llmapi", address = %listener.local_addr()?, "server listening");
    axum::serve(listener, app(config)).await?;
    Ok(())
}

fn handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl std::future::Future<Output = Response<Body>> + Send {
    info!(
        target: "llmapi",
        request = %redact::request(method.as_str(), &uri),
        "request received"
    );
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .expect("request builder with existing uri");

    proxy::handle(state, headers, request)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use axum::{
        extract::State,
        http::{HeaderMap, Method},
        response::IntoResponse,
        routing::any,
        Json, Router,
    };
    use serde_json::{json, Value};
    use tokio::sync::Mutex;

    use super::*;
    use crate::config::{Config, Provider, ProviderConfig};

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Value,
    }

    #[derive(Clone)]
    struct RecordedRequest {
        request: Arc<Mutex<Option<CapturedRequest>>>,
        response: Value,
    }

    async fn record_request(
        State(recorded): State<RecordedRequest>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        *recorded.request.lock().await = Some(CapturedRequest {
            method,
            uri,
            headers,
            body,
        });
        Json(recorded.response)
    }

    async fn start_upstream(response: Value) -> (String, Arc<Mutex<Option<CapturedRequest>>>) {
        let request = Arc::new(Mutex::new(None));
        let recorded = RecordedRequest {
            request: request.clone(),
            response,
        };
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                upstream_listener,
                Router::new()
                    .route("/{*path}", any(record_request))
                    .with_state(recorded),
            )
            .await
            .unwrap();
        });
        (format!("http://{upstream_addr}"), request)
    }

    fn test_config(base_url: &str) -> Config {
        Config {
            server: "127.0.0.1:0".into(),
            default: "deepseek".into(),
            providers: BTreeMap::from([
                (
                    "deepseek".into(),
                    ProviderConfig {
                        provider_type: Provider::OpenAiChat,
                        base_url: base_url.into(),
                        api_key: Some("sk-deepseek".into()),
                    },
                ),
                (
                    "openai".into(),
                    ProviderConfig {
                        provider_type: Provider::OpenAiResponses,
                        base_url: base_url.into(),
                        api_key: Some("sk-openai".into()),
                    },
                ),
                (
                    "anthropic".into(),
                    ProviderConfig {
                        provider_type: Provider::Anthropic,
                        base_url: base_url.into(),
                        api_key: Some("sk-anthropic".into()),
                    },
                ),
            ]),
        }
    }

    async fn start_proxy(config: Config) -> SocketAddr {
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(proxy_listener, app(config)).await.unwrap();
        });
        address
    }

    #[tokio::test]
    async fn responses_to_default_chat_provider() {
        let (upstream, captured) = start_upstream(json!({
            "id": "chatcmpl_1",
            "model": "deepseek-chat",
            "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        }))
        .await;
        let proxy = start_proxy(test_config(&upstream)).await;

        let response = reqwest::Client::new()
            .post(format!("http://{proxy}/responses"))
            .json(&json!({
                "model": "deepseek-chat",
                "input": [{"role": "user", "content": "hi"}]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let output: Value = response.json().await.unwrap();
        assert_eq!(output["object"], "response");
        assert_eq!(output["output_text"], "hello");
        let request = captured.lock().await;
        let request = request.as_ref().unwrap();
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.uri.path(), "/chat/completions");
        assert_eq!(request.body["messages"][0]["role"], "user");
        assert_eq!(request.headers["authorization"], "Bearer sk-deepseek");
    }

    #[tokio::test]
    async fn anthropic_messages_to_default_chat_provider() {
        let (upstream, captured) = start_upstream(json!({
            "id": "chatcmpl_2",
            "model": "deepseek-chat",
            "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}]
        }))
        .await;
        let proxy = start_proxy(test_config(&upstream)).await;

        let response = reqwest::Client::new()
            .post(format!("http://{proxy}/messages"))
            .json(&json!({
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 128
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let output: Value = response.json().await.unwrap();
        assert_eq!(output["type"], "message");
        assert_eq!(output["content"][0]["text"], "hello");
        assert_eq!(
            captured.lock().await.as_ref().unwrap().uri.path(),
            "/chat/completions"
        );
    }

    #[tokio::test]
    async fn responses_to_named_anthropic_provider() {
        let (upstream, captured) = start_upstream(json!({
            "id": "msg_1",
            "type": "message",
            "model": "claude-sonnet-4",
            "content": [{"type": "text", "text": "hello"}],
            "stop_reason": "end_turn"
        }))
        .await;
        let proxy = start_proxy(test_config(&upstream)).await;

        let response = reqwest::Client::new()
            .post(format!("http://{proxy}/anthropic/responses"))
            .json(&json!({
                "model": "claude-sonnet-4",
                "input": [{"role": "user", "content": "hi"}],
                "max_output_tokens": 128
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let output: Value = response.json().await.unwrap();
        assert_eq!(output["object"], "response");
        assert_eq!(output["output_text"], "hello");
        let request = captured.lock().await;
        let request = request.as_ref().unwrap();
        assert_eq!(request.uri.path(), "/messages");
        assert_eq!(request.body["messages"][0]["content"][0]["text"], "hi");
        assert_eq!(request.headers["x-api-key"], "sk-anthropic");
        assert_eq!(request.headers["anthropic-version"], "2023-06-01");
    }

    #[tokio::test]
    async fn anthropic_messages_to_named_responses_provider() {
        let (upstream, captured) = start_upstream(json!({
            "id": "resp_1",
            "object": "response",
            "model": "gpt-4.1",
            "output_text": "hello",
            "status": "completed"
        }))
        .await;
        let proxy = start_proxy(test_config(&upstream)).await;

        let response = reqwest::Client::new()
            .post(format!("http://{proxy}/openai/messages"))
            .json(&json!({
                "model": "gpt-4.1",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 128
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let output: Value = response.json().await.unwrap();
        assert_eq!(output["type"], "message");
        assert_eq!(output["content"][0]["text"], "hello");
        let request = captured.lock().await;
        let request = request.as_ref().unwrap();
        assert_eq!(request.uri.path(), "/responses");
        assert_eq!(request.body["input"][0]["content"], "hi");
        assert_eq!(request.headers["authorization"], "Bearer sk-openai");
    }

    #[tokio::test]
    async fn rejects_unknown_route_and_provider() {
        let (upstream, _) = start_upstream(json!({})).await;
        let proxy = start_proxy(test_config(&upstream)).await;

        let unknown_route = reqwest::get(format!("http://{proxy}/models"))
            .await
            .unwrap();
        let unknown_provider = reqwest::Client::new()
            .post(format!("http://{proxy}/missing/responses"))
            .json(&json!({"model": "test", "input": "hi"}))
            .send()
            .await
            .unwrap();

        assert_eq!(unknown_route.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(unknown_provider.status(), reqwest::StatusCode::NOT_FOUND);
    }
}
