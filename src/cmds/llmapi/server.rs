use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, Response, Uri},
    routing::any,
    Router,
};

use super::{
    config::Config,
    log::{self, LogEvent},
    proxy,
};

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
    log::emit(
        LogEvent::ServerListening,
        listener.local_addr()?.to_string(),
    );
    axum::serve(listener, app(config)).await?;
    Ok(())
}

async fn handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    log::emit(
        LogEvent::RequestReceived,
        log::request_line(method.as_str(), &uri),
    );
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .expect("request builder with existing uri");

    proxy::handle(state, headers, request).await
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use axum::{extract::State, http::Method, routing::any, Router};
    use tokio::sync::Mutex;

    use super::*;
    use crate::cmds::llmapi::config::{Config, Provider};

    #[derive(Clone, Default)]
    struct RecordedRequest {
        method: Arc<Mutex<Option<Method>>>,
        uri: Arc<Mutex<Option<Uri>>>,
    }

    async fn record_request(
        State(recorded): State<RecordedRequest>,
        method: Method,
        uri: Uri,
    ) -> &'static str {
        *recorded.method.lock().await = Some(method);
        *recorded.uri.lock().await = Some(uri);
        "ok"
    }

    #[tokio::test]
    async fn proxies_unknown_paths_to_upstream() {
        let recorded = RecordedRequest::default();
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_recorded = recorded.clone();
        tokio::spawn(async move {
            axum::serve(
                upstream_listener,
                Router::new()
                    .route("/{*path}", any(record_request))
                    .with_state(upstream_recorded),
            )
            .await
            .unwrap();
        });

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr: SocketAddr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                proxy_listener,
                app(Config {
                    server: proxy_addr.to_string(),
                    base_url: format!("http://{upstream_addr}"),
                    provider: Provider::OpenAiCompatible,
                    api_key: None,
                }),
            )
            .await
            .unwrap();
        });

        let response = reqwest::get(format!("http://{proxy_addr}/models?limit=10"))
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(*recorded.method.lock().await, Some(Method::GET));
        assert_eq!(
            recorded.uri.lock().await.as_ref().map(Uri::path),
            Some("/models")
        );
        assert_eq!(
            recorded.uri.lock().await.as_ref().and_then(Uri::query),
            Some("limit=10")
        );
    }
}
