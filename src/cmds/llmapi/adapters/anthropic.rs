use serde_json::{json, Value};

use super::super::{
    adapters::{AdapterError, RequestAdapter, ResponseAdapter, StreamAdapter},
    model::{text_content, LLMMessage, LLMRequest, LLMResponse, LLMRole, LLMStreamEvent},
};

pub struct AnthropicAdapter;

impl RequestAdapter for AnthropicAdapter {
    fn to_llm_request(value: Value) -> Result<LLMRequest, AdapterError> {
        let model = value["model"]
            .as_str()
            .ok_or(AdapterError::MissingField("model"))?
            .to_string();
        let mut messages = Vec::new();
        for item in value["messages"]
            .as_array()
            .ok_or(AdapterError::MissingField("messages"))?
        {
            let role = match item["role"].as_str().unwrap_or("user") {
                "assistant" => LLMRole::Assistant,
                _ => LLMRole::User,
            };
            messages.push(LLMMessage {
                role,
                content: text_content(extract_anthropic_text(&item["content"])),
                name: None,
                tool_call_id: None,
                metadata: json!({}),
            });
        }
        Ok(LLMRequest {
            model,
            system: value["system"].as_str().map(ToString::to_string),
            messages,
            temperature: value["temperature"].as_f64(),
            max_tokens: value["max_tokens"].as_u64(),
            top_p: value["top_p"].as_f64(),
            stop: value.get("stop_sequences").cloned(),
            stream: value["stream"].as_bool().unwrap_or(false),
            tools: value["tools"].as_array().cloned().unwrap_or_default(),
            metadata: json!({ "source": "anthropic" }),
        })
    }

    fn from_llm_request(request: &LLMRequest) -> Result<Value, AdapterError> {
        let messages: Vec<Value> = request
            .messages
            .iter()
            .map(|message| {
                json!({
                    "role": match message.role {
                        LLMRole::Assistant => "assistant",
                        _ => "user",
                    },
                    "content": [{"type": "text", "text": super::openai_chat::join_text(&message.content)}]
                })
            })
            .collect();
        let mut value = json!({
            "model": request.model,
            "messages": messages,
            "max_tokens": request.max_tokens.unwrap_or(1024),
            "stream": request.stream
        });
        if let Some(system) = &request.system {
            value["system"] = json!(system);
        }
        if let Some(temperature) = request.temperature {
            value["temperature"] = json!(temperature);
        }
        if let Some(top_p) = request.top_p {
            value["top_p"] = json!(top_p);
        }
        if !request.tools.is_empty() {
            value["tools"] = json!(request.tools);
        }
        Ok(value)
    }
}

impl ResponseAdapter for AnthropicAdapter {
    fn to_llm_response(value: Value) -> Result<LLMResponse, AdapterError> {
        Ok(LLMResponse {
            id: value["id"].as_str().map(ToString::to_string),
            model: value["model"].as_str().map(ToString::to_string),
            content: text_content(extract_anthropic_text(&value["content"])),
            finish_reason: value["stop_reason"].as_str().map(ToString::to_string),
            usage: value.get("usage").cloned(),
            metadata: json!({ "source": "anthropic" }),
        })
    }

    fn from_llm_response(response: &LLMResponse) -> Result<Value, AdapterError> {
        Ok(json!({
            "id": response.id.clone().unwrap_or_else(|| format!("msg_{}", uuid::Uuid::new_v4())),
            "type": "message",
            "role": "assistant",
            "model": response.model.clone().unwrap_or_default(),
            "content": [{"type": "text", "text": super::openai_chat::join_text(&response.content)}],
            "stop_reason": response.finish_reason.clone().unwrap_or_else(|| "end_turn".into()),
            "usage": response.usage.clone().unwrap_or_else(|| json!({}))
        }))
    }
}

impl StreamAdapter for AnthropicAdapter {
    fn parse_stream_event(event: &str) -> Result<Option<LLMStreamEvent>, AdapterError> {
        let Some(data) = event.strip_prefix("data: ") else {
            return Ok(None);
        };
        let value: Value =
            serde_json::from_str(data).map_err(|_| AdapterError::InvalidField("stream_json"))?;
        match value["type"].as_str() {
            Some("content_block_delta") => Ok(Some(LLMStreamEvent::TextDelta {
                text: value["delta"]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            })),
            Some("message_stop") => Ok(Some(LLMStreamEvent::MessageEnd {
                finish_reason: None,
                usage: None,
            })),
            _ => Ok(None),
        }
    }

    fn format_stream_event(event: &LLMStreamEvent) -> Result<Option<String>, AdapterError> {
        match event {
            LLMStreamEvent::TextDelta { text } => Ok(Some(format!(
                "event: content_block_delta\ndata: {}\n\n",
                json!({"type":"content_block_delta","delta":{"type":"text_delta","text":text}})
            ))),
            LLMStreamEvent::MessageEnd { .. } => Ok(Some(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
            )),
            _ => Ok(None),
        }
    }
}

fn extract_anthropic_text(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_string();
    }
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["text"].as_str())
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::super::super::model::LLMContent;
    use super::*;
    use serde_json::json;

    #[test]
    fn anthropic_request_to_llm_request() {
        let value = json!({
            "model": "claude-sonnet-4",
            "system": "sys",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            "max_tokens": 128
        });
        let request = AnthropicAdapter::to_llm_request(value).unwrap();
        assert_eq!(request.system.as_deref(), Some("sys"));
        assert_eq!(request.max_tokens, Some(128));
    }

    #[test]
    fn llm_response_to_anthropic_response() {
        let response = LLMResponse {
            id: Some("msg_1".into()),
            model: Some("claude-sonnet-4".into()),
            content: vec![LLMContent::Text {
                text: "hello".into(),
            }],
            finish_reason: Some("end_turn".into()),
            usage: Some(json!({"input_tokens": 1, "output_tokens": 1})),
            metadata: json!({}),
        };
        let value = AnthropicAdapter::from_llm_response(&response).unwrap();
        assert_eq!(value["type"], "message");
        assert_eq!(value["content"][0]["text"], "hello");
    }
}
