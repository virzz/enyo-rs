use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, Response, StatusCode, Uri},
    response::IntoResponse,
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
    if method != Method::POST {
        log::emit(LogEvent::UpstreamResponseReceived, "405 method not allowed");
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .expect("request builder with existing uri");

    proxy::handle(state, headers, request).await
}
