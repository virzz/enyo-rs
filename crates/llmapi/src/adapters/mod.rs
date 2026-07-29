pub mod anthropic;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;

use serde_json::{json, Value};
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

pub(super) fn tools_from_openai_chat(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tool| normalize_tool(&tool["function"], "parameters"))
        .collect()
}

pub(super) fn tools_from_openai_responses(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter(|tool| tool["type"].as_str() == Some("function"))
        .filter_map(|tool| normalize_tool(tool, "parameters"))
        .collect()
}

pub(super) fn tools_from_anthropic(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tool| normalize_tool(tool, "input_schema"))
        .collect()
}

pub(super) fn tools_to_openai_chat(tools: &[Value]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| json!({"type": "function", "function": tool}))
        .collect()
}

pub(super) fn tools_to_openai_responses(tools: &[Value]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| {
            let mut output = tool.clone();
            output["type"] = json!("function");
            output
        })
        .collect()
}

pub(super) fn tools_to_anthropic(tools: &[Value]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| {
            let mut output = tool.clone();
            output["input_schema"] = output
                .as_object_mut()
                .and_then(|object| object.remove("parameters"))
                .unwrap_or_else(|| json!({"type": "object"}));
            output
        })
        .collect()
}

pub(super) fn sse_data(event: &str) -> Option<&str> {
    event.lines().find_map(|line| line.strip_prefix("data: "))
}

fn normalize_tool(tool: &Value, schema_field: &str) -> Option<Value> {
    let name = tool["name"].as_str()?;
    let mut output = json!({
        "name": name,
        "parameters": tool.get(schema_field).cloned().unwrap_or_else(|| json!({"type": "object"}))
    });
    if let Some(description) = tool["description"].as_str() {
        output["description"] = json!(description);
    }
    if let Some(strict) = tool["strict"].as_bool() {
        output["strict"] = json!(strict);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_function_tool_schemas() {
        let chat = json!([{
            "type": "function",
            "function": {
                "name": "weather",
                "description": "Get weather",
                "parameters": {"type": "object"}
            }
        }]);
        let normalized = tools_from_openai_chat(&chat);

        assert_eq!(tools_to_anthropic(&normalized)[0]["name"], "weather");
        assert_eq!(
            tools_to_anthropic(&normalized)[0]["input_schema"]["type"],
            "object"
        );
        assert_eq!(
            tools_to_openai_responses(&normalized)[0]["type"],
            "function"
        );
    }

    #[test]
    fn reads_data_after_sse_event_name() {
        assert_eq!(
            sse_data("event: message_stop\ndata: {\"type\":\"message_stop\"}"),
            Some("{\"type\":\"message_stop\"}")
        );
    }
}
