pub mod anthropic;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;

use serde_json::Value;
use thiserror::Error;

use super::model::{LLMRequest, LLMResponse, LLMStreamEvent};

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
}

pub trait RequestAdapter {
    fn to_llm_request(value: Value) -> Result<LLMRequest, AdapterError>;
    fn from_llm_request(request: &LLMRequest) -> Result<Value, AdapterError>;
}

pub trait ResponseAdapter {
    fn to_llm_response(value: Value) -> Result<LLMResponse, AdapterError>;
    fn from_llm_response(response: &LLMResponse) -> Result<Value, AdapterError>;
}

pub trait StreamAdapter {
    fn parse_stream_event(event: &str) -> Result<Option<LLMStreamEvent>, AdapterError>;
    fn format_stream_event(event: &LLMStreamEvent) -> Result<Option<String>, AdapterError>;
}
