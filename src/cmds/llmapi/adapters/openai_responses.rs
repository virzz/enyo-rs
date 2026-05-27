use serde_json::{json, Value};

use super::super::{
    adapters::{AdapterError, RequestAdapter, ResponseAdapter, StreamAdapter},
    model::{text_content, LLMMessage, LLMRequest, LLMResponse, LLMRole, LLMStreamEvent},
};

pub struct OpenAiResponsesAdapter;

impl RequestAdapter for OpenAiResponsesAdapter {
    fn to_llm_request(value: Value) -> Result<LLMRequest, AdapterError> {
        let model = value["model"]
            .as_str()
            .ok_or(AdapterError::MissingField("model"))?
            .to_string();
        let mut messages = Vec::new();
        for item in value["input"]
            .as_array()
            .ok_or(AdapterError::MissingField("input"))?
        {
            let role = match item["role"].as_str().unwrap_or("user") {
                "assistant" => LLMRole::Assistant,
                "tool" => LLMRole::Tool,
                _ => LLMRole::User,
            };
            let content = item["content"].as_str().unwrap_or_default().to_string();
            messages.push(LLMMessage {
                role,
                content: text_content(content),
                name: None,
                tool_call_id: None,
                metadata: json!({}),
            });
        }
        Ok(LLMRequest {
            model,
            system: value["instructions"].as_str().map(ToString::to_string),
            messages,
            temperature: value["temperature"].as_f64(),
            max_tokens: value["max_output_tokens"].as_u64(),
            top_p: value["top_p"].as_f64(),
            stop: value.get("stop").cloned(),
            stream: value["stream"].as_bool().unwrap_or(false),
            tools: value["tools"].as_array().cloned().unwrap_or_default(),
            metadata: json!({ "source": "openai_responses" }),
        })
    }

    fn from_llm_request(request: &LLMRequest) -> Result<Value, AdapterError> {
        let input: Vec<Value> = request
            .messages
            .iter()
            .map(|message| {
                json!({
                    "role": super::openai_chat::role_name(message.role),
                    "content": super::openai_chat::join_text(&message.content)
                })
            })
            .collect();
        let mut value = json!({
            "model": request.model,
            "input": input,
            "stream": request.stream
        });
        if let Some(system) = &request.system {
            value["instructions"] = json!(system);
        }
        if let Some(max_tokens) = request.max_tokens {
            value["max_output_tokens"] = json!(max_tokens);
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

impl ResponseAdapter for OpenAiResponsesAdapter {
    fn to_llm_response(value: Value) -> Result<LLMResponse, AdapterError> {
        Ok(LLMResponse {
            id: value["id"].as_str().map(ToString::to_string),
            model: value["model"].as_str().map(ToString::to_string),
            content: text_content(value["output_text"].as_str().unwrap_or_default()),
            finish_reason: value["status"].as_str().map(ToString::to_string),
            usage: value.get("usage").cloned(),
            metadata: json!({ "source": "openai_responses" }),
        })
    }

    fn from_llm_response(response: &LLMResponse) -> Result<Value, AdapterError> {
        Ok(json!({
            "id": response.id.clone().unwrap_or_else(|| format!("resp_{}", uuid::Uuid::new_v4())),
            "object": "response",
            "model": response.model.clone().unwrap_or_default(),
            "output_text": super::openai_chat::join_text(&response.content),
            "status": response.finish_reason.clone().unwrap_or_else(|| "completed".into()),
            "usage": response.usage.clone().unwrap_or_else(|| json!({}))
        }))
    }
}

impl StreamAdapter for OpenAiResponsesAdapter {
    fn parse_stream_event(event: &str) -> Result<Option<LLMStreamEvent>, AdapterError> {
        let Some(data) = event.strip_prefix("data: ") else {
            return Ok(None);
        };
        let value: Value =
            serde_json::from_str(data).map_err(|_| AdapterError::InvalidField("stream_json"))?;
        match value["type"].as_str() {
            Some("response.output_text.delta") => Ok(Some(LLMStreamEvent::TextDelta {
                text: value["delta"].as_str().unwrap_or_default().to_string(),
            })),
            Some("response.completed") => Ok(Some(LLMStreamEvent::MessageEnd {
                finish_reason: Some("completed".into()),
                usage: value.get("usage").cloned(),
            })),
            _ => Ok(None),
        }
    }

    fn format_stream_event(event: &LLMStreamEvent) -> Result<Option<String>, AdapterError> {
        match event {
            LLMStreamEvent::TextDelta { text } => Ok(Some(format!(
                "data: {}\n\n",
                json!({"type":"response.output_text.delta","delta":text})
            ))),
            LLMStreamEvent::MessageEnd { .. } => Ok(Some(format!(
                "data: {}\n\n",
                json!({"type":"response.completed"})
            ))),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::model::LLMContent;
    use super::*;
    use serde_json::json;

    #[test]
    fn responses_request_to_llm_request() {
        let value = json!({
            "model": "gpt-4.1",
            "instructions": "sys",
            "input": [{"role": "user", "content": "hi"}],
            "stream": false
        });
        let request = OpenAiResponsesAdapter::to_llm_request(value).unwrap();
        assert_eq!(request.model, "gpt-4.1");
        assert_eq!(request.system.as_deref(), Some("sys"));
        assert_eq!(request.messages.len(), 1);
    }

    #[test]
    fn responses_response_to_llm_response() {
        let value = json!({
            "id": "resp_1",
            "model": "gpt-4.1",
            "output_text": "hello",
            "usage": {"input_tokens": 1}
        });
        let response = OpenAiResponsesAdapter::to_llm_response(value).unwrap();
        assert_eq!(
            response.content,
            vec![LLMContent::Text {
                text: "hello".into()
            }]
        );
    }
}
