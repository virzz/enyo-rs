use serde_json::{json, Value};

use super::super::{
    adapters::{AdapterError, RequestAdapter, ResponseAdapter, StreamAdapter},
    model::{
        text_content, LLMContent, LLMMessage, LLMRequest, LLMResponse, LLMRole, LLMStreamEvent,
    },
};

pub struct OpenAiChatAdapter;

impl RequestAdapter for OpenAiChatAdapter {
    fn to_llm_request(value: Value) -> Result<LLMRequest, AdapterError> {
        let model = value["model"]
            .as_str()
            .ok_or(AdapterError::MissingField("model"))?
            .to_string();
        let stream = value["stream"].as_bool().unwrap_or(false);
        let mut system = None;
        let mut messages = Vec::new();

        for item in value["messages"]
            .as_array()
            .ok_or(AdapterError::MissingField("messages"))?
        {
            let role = item["role"]
                .as_str()
                .ok_or(AdapterError::MissingField("role"))?;
            let text = extract_text(&item["content"]);
            match role {
                "system" => system = Some(text),
                "user" => messages.push(message(LLMRole::User, text)),
                "assistant" => messages.push(message(LLMRole::Assistant, text)),
                "tool" => messages.push(message(LLMRole::Tool, text)),
                _ => return Err(AdapterError::InvalidField("role")),
            }
        }

        Ok(LLMRequest {
            model,
            system,
            messages,
            temperature: value["temperature"].as_f64(),
            max_tokens: value["max_tokens"].as_u64(),
            top_p: value["top_p"].as_f64(),
            stop: value.get("stop").cloned(),
            stream,
            tools: value["tools"].as_array().cloned().unwrap_or_default(),
            metadata: json!({ "source": "openai_chat" }),
        })
    }

    fn from_llm_request(request: &LLMRequest) -> Result<Value, AdapterError> {
        let mut messages = Vec::new();
        if let Some(system) = &request.system {
            messages.push(json!({ "role": "system", "content": system }));
        }
        for message in &request.messages {
            messages.push(json!({
                "role": role_name(message.role),
                "content": join_text(&message.content),
            }));
        }
        let mut value = json!({
            "model": request.model,
            "messages": messages,
            "stream": request.stream,
        });
        copy_common_request_fields(&mut value, request);
        Ok(value)
    }
}

impl ResponseAdapter for OpenAiChatAdapter {
    fn to_llm_response(value: Value) -> Result<LLMResponse, AdapterError> {
        let choice = value["choices"]
            .as_array()
            .and_then(|v| v.first())
            .ok_or(AdapterError::InvalidField("choices"))?;
        Ok(LLMResponse {
            id: value["id"].as_str().map(ToString::to_string),
            model: value["model"].as_str().map(ToString::to_string),
            content: text_content(choice["message"]["content"].as_str().unwrap_or_default()),
            finish_reason: choice["finish_reason"].as_str().map(ToString::to_string),
            usage: value.get("usage").cloned(),
            metadata: json!({ "source": "openai_chat" }),
        })
    }

    fn from_llm_response(response: &LLMResponse) -> Result<Value, AdapterError> {
        Ok(json!({
            "id": response.id.clone().unwrap_or_else(|| format!("chatcmpl_{}", uuid::Uuid::new_v4())),
            "object": "chat.completion",
            "model": response.model.clone().unwrap_or_default(),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": join_text(&response.content)},
                "finish_reason": response.finish_reason.clone().unwrap_or_else(|| "stop".into())
            }],
            "usage": response.usage.clone().unwrap_or_else(|| json!({}))
        }))
    }
}

impl StreamAdapter for OpenAiChatAdapter {
    fn parse_stream_event(event: &str) -> Result<Option<LLMStreamEvent>, AdapterError> {
        let Some(data) = event.strip_prefix("data: ") else {
            return Ok(None);
        };
        if data.trim() == "[DONE]" {
            return Ok(Some(LLMStreamEvent::MessageEnd {
                finish_reason: None,
                usage: None,
            }));
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| AdapterError::InvalidField("stream_json"))?;
        let delta = value["choices"][0]["delta"]["content"]
            .as_str()
            .unwrap_or_default();
        if delta.is_empty() {
            return Ok(None);
        }
        Ok(Some(LLMStreamEvent::TextDelta {
            text: delta.to_string(),
        }))
    }

    fn format_stream_event(event: &LLMStreamEvent) -> Result<Option<String>, AdapterError> {
        match event {
            LLMStreamEvent::TextDelta { text } => Ok(Some(format!(
                "data: {}\n\n",
                json!({"choices":[{"delta":{"content": text},"index":0}]})
            ))),
            LLMStreamEvent::MessageEnd { .. } => Ok(Some("data: [DONE]\n\n".to_string())),
            _ => Ok(None),
        }
    }
}

fn message(role: LLMRole, text: String) -> LLMMessage {
    LLMMessage {
        role,
        content: text_content(text),
        name: None,
        tool_call_id: None,
        metadata: json!({}),
    }
}

fn extract_text(value: &Value) -> String {
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

pub(super) fn join_text(content: &[LLMContent]) -> String {
    content
        .iter()
        .map(|item| match item {
            LLMContent::Text { text } => text.as_str(),
        })
        .collect::<Vec<_>>()
        .join("")
}

pub(super) fn role_name(role: LLMRole) -> &'static str {
    match role {
        LLMRole::System => "system",
        LLMRole::User => "user",
        LLMRole::Assistant => "assistant",
        LLMRole::Tool => "tool",
    }
}

fn copy_common_request_fields(value: &mut Value, request: &LLMRequest) {
    if let Some(temperature) = request.temperature {
        value["temperature"] = json!(temperature);
    }
    if let Some(max_tokens) = request.max_tokens {
        value["max_tokens"] = json!(max_tokens);
    }
    if let Some(top_p) = request.top_p {
        value["top_p"] = json!(top_p);
    }
    if let Some(stop) = &request.stop {
        value["stop"] = stop.clone();
    }
    if !request.tools.is_empty() {
        value["tools"] = json!(request.tools);
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::model::{LLMContent, LLMRole};
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_request_to_llm_request() {
        let value = json!({
            "model": "gpt-4.1",
            "messages": [
                {"role": "system", "content": "You are terse."},
                {"role": "user", "content": "hi"}
            ],
            "temperature": 0.2,
            "stream": true
        });

        let request = OpenAiChatAdapter::to_llm_request(value).unwrap();

        assert_eq!(request.model, "gpt-4.1");
        assert_eq!(request.system.as_deref(), Some("You are terse."));
        assert_eq!(request.messages[0].role, LLMRole::User);
        assert_eq!(
            request.messages[0].content,
            vec![LLMContent::Text { text: "hi".into() }]
        );
        assert!(request.stream);
    }

    #[test]
    fn llm_request_to_chat_request() {
        let request = LLMRequest {
            model: "gpt-4.1".into(),
            system: Some("sys".into()),
            messages: vec![super::super::super::model::LLMMessage {
                role: LLMRole::User,
                content: super::super::super::model::text_content("hi"),
                name: None,
                tool_call_id: None,
                metadata: json!({}),
            }],
            temperature: Some(0.1),
            max_tokens: Some(128),
            top_p: None,
            stop: None,
            stream: false,
            tools: vec![],
            metadata: json!({}),
        };

        let value = OpenAiChatAdapter::from_llm_request(&request).unwrap();

        assert_eq!(value["model"], "gpt-4.1");
        assert_eq!(value["messages"][0]["role"], "system");
        assert_eq!(value["messages"][1]["role"], "user");
        assert_eq!(value["max_tokens"], 128);
    }

    #[test]
    fn chat_response_to_llm_response() {
        let value = json!({
            "id": "chatcmpl_1",
            "model": "gpt-4.1",
            "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        });

        let response = OpenAiChatAdapter::to_llm_response(value).unwrap();

        assert_eq!(response.id.as_deref(), Some("chatcmpl_1"));
        assert_eq!(
            response.content,
            vec![LLMContent::Text {
                text: "hello".into()
            }]
        );
        assert_eq!(response.finish_reason.as_deref(), Some("stop"));
    }
}
