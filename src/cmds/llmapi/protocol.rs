use super::config::Provider;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputFormat {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
    GeminiGenerate { model: String, stream: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamFormat {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
    GeminiGenerate,
}

pub fn detect_input(path: &str) -> Option<InputFormat> {
    match path {
        "/v1/chat/completions" => Some(InputFormat::OpenAiChat),
        "/v1/responses" => Some(InputFormat::OpenAiResponses),
        "/v1/messages" | "/anthropic/v1/messages" => Some(InputFormat::AnthropicMessages),
        _ => detect_gemini(path),
    }
}

fn detect_gemini(path: &str) -> Option<InputFormat> {
    let rest = path.strip_prefix("/v1beta/models/")?;
    if let Some(model) = rest.strip_suffix(":generateContent") {
        return gemini_input(model, false);
    }
    if let Some(model) = rest.strip_suffix(":streamGenerateContent") {
        return gemini_input(model, true);
    }
    None
}

fn gemini_input(model: &str, stream: bool) -> Option<InputFormat> {
    if model.is_empty() {
        return None;
    }
    Some(InputFormat::GeminiGenerate {
        model: model.to_string(),
        stream,
    })
}

pub fn upstream_for(provider: Provider, input: &InputFormat) -> (UpstreamFormat, String) {
    match provider {
        Provider::OpenAiCompatible => match input {
            InputFormat::OpenAiResponses => {
                (UpstreamFormat::OpenAiResponses, "/v1/responses".to_string())
            }
            _ => (
                UpstreamFormat::OpenAiChat,
                "/v1/chat/completions".to_string(),
            ),
        },
        Provider::OpenAiChat => (
            UpstreamFormat::OpenAiChat,
            "/v1/chat/completions".to_string(),
        ),
        Provider::OpenAiResponses => (UpstreamFormat::OpenAiResponses, "/v1/responses".to_string()),
        Provider::Claude => (
            UpstreamFormat::AnthropicMessages,
            "/v1/messages".to_string(),
        ),
        Provider::Gemini => (
            UpstreamFormat::GeminiGenerate,
            "/v1beta/models/{model}:generateContent".to_string(),
        ),
    }
}

pub fn is_transparent(input: &InputFormat, upstream: &UpstreamFormat) -> bool {
    matches!(
        (input, upstream),
        (InputFormat::OpenAiChat, UpstreamFormat::OpenAiChat)
            | (
                InputFormat::OpenAiResponses,
                UpstreamFormat::OpenAiResponses
            )
            | (
                InputFormat::AnthropicMessages,
                UpstreamFormat::AnthropicMessages
            )
            | (
                InputFormat::GeminiGenerate { .. },
                UpstreamFormat::GeminiGenerate
            )
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn detect_static_paths() {
        assert_eq!(
            detect_input("/v1/chat/completions"),
            Some(InputFormat::OpenAiChat)
        );
        assert_eq!(
            detect_input("/v1/responses"),
            Some(InputFormat::OpenAiResponses)
        );
        assert_eq!(
            detect_input("/v1/messages"),
            Some(InputFormat::AnthropicMessages)
        );
        assert_eq!(
            detect_input("/anthropic/v1/messages"),
            Some(InputFormat::AnthropicMessages)
        );
        assert_eq!(detect_input("/v1/unknown"), None);
    }

    #[test]
    fn detect_gemini_paths() {
        assert_eq!(
            detect_input("/v1beta/models/gemini-2.5-pro:generateContent"),
            Some(InputFormat::GeminiGenerate {
                model: "gemini-2.5-pro".to_string(),
                stream: false,
            })
        );
        assert_eq!(
            detect_input("/v1beta/models/gemini-2.5-flash:streamGenerateContent"),
            Some(InputFormat::GeminiGenerate {
                model: "gemini-2.5-flash".to_string(),
                stream: true,
            })
        );
        assert_eq!(detect_input("/v1beta/models/:generateContent"), None);
    }

    #[test]
    fn maps_openai_compatible_provider() {
        assert_eq!(
            upstream_for(Provider::OpenAiCompatible, &InputFormat::OpenAiResponses),
            (UpstreamFormat::OpenAiResponses, "/v1/responses".to_string())
        );
        assert_eq!(
            upstream_for(Provider::OpenAiCompatible, &InputFormat::AnthropicMessages),
            (
                UpstreamFormat::OpenAiChat,
                "/v1/chat/completions".to_string()
            )
        );
    }

    #[test]
    fn maps_explicit_providers() {
        assert_eq!(
            upstream_for(Provider::OpenAiChat, &InputFormat::OpenAiResponses),
            (
                UpstreamFormat::OpenAiChat,
                "/v1/chat/completions".to_string()
            )
        );
        assert_eq!(
            upstream_for(Provider::OpenAiResponses, &InputFormat::OpenAiChat),
            (UpstreamFormat::OpenAiResponses, "/v1/responses".to_string())
        );
        assert_eq!(
            upstream_for(Provider::Claude, &InputFormat::OpenAiChat),
            (
                UpstreamFormat::AnthropicMessages,
                "/v1/messages".to_string()
            )
        );
        assert_eq!(
            upstream_for(
                Provider::Gemini,
                &InputFormat::GeminiGenerate {
                    model: "gemini-2.5-flash".to_string(),
                    stream: true,
                },
            ),
            (
                UpstreamFormat::GeminiGenerate,
                "/v1beta/models/{model}:generateContent".to_string()
            )
        );
        assert_eq!(
            upstream_for(Provider::Gemini, &InputFormat::OpenAiChat),
            (
                UpstreamFormat::GeminiGenerate,
                "/v1beta/models/{model}:generateContent".to_string()
            )
        );
    }

    #[test]
    fn reports_transparent_routes() {
        assert!(is_transparent(
            &InputFormat::OpenAiChat,
            &UpstreamFormat::OpenAiChat
        ));
        assert!(is_transparent(
            &InputFormat::OpenAiResponses,
            &UpstreamFormat::OpenAiResponses
        ));
        assert!(is_transparent(
            &InputFormat::AnthropicMessages,
            &UpstreamFormat::AnthropicMessages
        ));
        assert!(is_transparent(
            &InputFormat::GeminiGenerate {
                model: "gemini-2.5-pro".to_string(),
                stream: false,
            },
            &UpstreamFormat::GeminiGenerate
        ));
        assert!(!is_transparent(
            &InputFormat::AnthropicMessages,
            &UpstreamFormat::OpenAiChat
        ));
    }
}
