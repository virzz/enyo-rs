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
        let messages = responses_input(&value["input"])?;
        Ok(LLMRequest {
            model,
            system: value["instructions"].as_str().map(ToString::to_string),
            messages,
            temperature: value["temperature"].as_f64(),
            max_tokens: value["max_output_tokens"].as_u64(),
            top_p: value["top_p"].as_f64(),
            stop: value.get("stop").cloned(),
            stream: value["stream"].as_bool().unwrap_or(false),
            tools: super::tools_from_openai_responses(&value["tools"]),
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
            value["tools"] = json!(super::tools_to_openai_responses(&request.tools));
        }
        Ok(value)
    }
}

impl ResponseAdapter for OpenAiResponsesAdapter {
    fn to_llm_response(value: Value) -> Result<LLMResponse, AdapterError> {
        let output_text = value["output_text"]
            .as_str()
            .map(ToString::to_string)
            .unwrap_or_else(|| extract_output_text(&value["output"]));
        Ok(LLMResponse {
            id: value["id"].as_str().map(ToString::to_string),
            model: value["model"].as_str().map(ToString::to_string),
            content: text_content(output_text),
            finish_reason: value["status"].as_str().map(ToString::to_string),
            usage: value.get("usage").cloned(),
            metadata: json!({ "source": "openai_responses" }),
        })
    }

    fn from_llm_response(response: &LLMResponse) -> Result<Value, AdapterError> {
        let id = response
            .id
            .clone()
            .unwrap_or_else(|| format!("resp_{}", uuid::Uuid::new_v4()));
        let text = super::openai_chat::join_text(&response.content);
        Ok(json!({
            "id": id,
            "object": "response",
            "model": response.model.clone().unwrap_or_default(),
            "output": [{
                "id": format!("msg_{}", uuid::Uuid::new_v4()),
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}]
            }],
            "output_text": text,
            "status": response.finish_reason.clone().unwrap_or_else(|| "completed".into()),
            "usage": response.usage.clone().unwrap_or_else(|| json!({}))
        }))
    }
}

impl StreamAdapter for OpenAiResponsesAdapter {
    fn parse_stream_event(event: &str) -> Result<Option<LLMStreamEvent>, AdapterError> {
        let Some(data) = super::sse_data(event) else {
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

fn responses_input(value: &Value) -> Result<Vec<LLMMessage>, AdapterError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![message(LLMRole::User, text.to_string())]);
    }
    let items = value
        .as_array()
        .ok_or(AdapterError::MissingField("input"))?;
    Ok(items
        .iter()
        .filter(|item| item["type"].as_str().unwrap_or("message") == "message")
        .map(|item| {
            let role = match item["role"].as_str().unwrap_or("user") {
                "assistant" => LLMRole::Assistant,
                "tool" => LLMRole::Tool,
                _ => LLMRole::User,
            };
            message(role, extract_responses_content(&item["content"]))
        })
        .collect())
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

fn extract_responses_content(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_string();
    }
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["text"].as_str())
        .collect::<Vec<_>>()
        .join("")
}

fn extract_output_text(value: &Value) -> String {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["type"].as_str() == Some("message"))
        .flat_map(|item| item["content"].as_array().into_iter().flatten())
        .filter_map(|content| content["text"].as_str())
        .collect::<Vec<_>>()
        .join("")
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

    #[test]
    fn parses_string_and_content_block_inputs() {
        let string = OpenAiResponsesAdapter::to_llm_request(json!({
            "model": "gpt-4.1",
            "input": "hello"
        }))
        .unwrap();
        let blocks = OpenAiResponsesAdapter::to_llm_request(json!({
            "model": "gpt-4.1",
            "input": [{
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "hello"}]
            }]
        }))
        .unwrap();

        assert_eq!(string.messages[0].content, text_content("hello"));
        assert_eq!(blocks.messages[0].content, text_content("hello"));
    }

    #[test]
    fn parses_real_responses_output_shape() {
        let response = OpenAiResponsesAdapter::to_llm_response(json!({
            "id": "resp_1",
            "model": "gpt-4.1",
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "hello"}]
            }]
        }))
        .unwrap();

        assert_eq!(response.content, text_content("hello"));
        let output = OpenAiResponsesAdapter::from_llm_response(&response).unwrap();
        assert_eq!(output["output"][0]["content"][0]["text"], "hello");
    }
}
