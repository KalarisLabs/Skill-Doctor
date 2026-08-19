//! Provider-agnostic LLM client using OpenAI-compatible REST API.
//!
//! Works with Groq, OpenAI, Ollama, vLLM, and any provider that implements
//! the OpenAI chat completions API contract.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Configuration for the LLM client.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Base URL for the API (e.g., "https://api.groq.com/openai/v1").
    pub base_url: String,
    /// API key for authentication.
    pub api_key: String,
    /// Model name (e.g., "llama-3.3-70b-versatile").
    pub model: String,
}

impl LlmConfig {
    /// Load configuration from environment variables with optional CLI overrides.
    ///
    /// - `SKILL_DOCTOR_LLM_URL` (default: Groq)
    /// - `SKILL_DOCTOR_LLM_KEY` (required)
    /// - `SKILL_DOCTOR_LLM_MODEL` (default: llama-3.3-70b-versatile)
    ///
    /// Also checks legacy `GROQ_API_KEY` for backward compatibility.
    pub fn from_env() -> Option<Self> {
        Self::from_env_with_overrides(None, None)
    }

    /// Load configuration from environment variables with explicit CLI overrides for URL and model.
    pub fn from_env_with_overrides(
        custom_url: Option<String>,
        custom_model: Option<String>,
    ) -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok(), custom_url, custom_model)
    }

    /// Helper that loads configuration using an arbitrary environment lookup function.
    pub fn from_lookup<F>(
        lookup: F,
        custom_url: Option<String>,
        custom_model: Option<String>,
    ) -> Option<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let api_key = lookup("SKILL_DOCTOR_LLM_KEY")
            .or_else(|| lookup("GROQ_API_KEY"))?;

        let base_url = custom_url
            .or_else(|| lookup("SKILL_DOCTOR_LLM_URL"))
            .unwrap_or_else(|| "https://api.groq.com/openai/v1".to_string());

        let model = custom_model
            .or_else(|| lookup("SKILL_DOCTOR_LLM_MODEL"))
            .unwrap_or_else(|| "llama-3.3-70b-versatile".to_string());

        Some(Self {
            base_url,
            api_key,
            model,
        })
    }
}

/// OpenAI-compatible chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// Chat completion request body.
#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [Message],
    temperature: f64,
    response_format: ResponseFormat,
}

#[derive(Debug, Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    format_type: String,
}

/// Chat completion response body.
#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
}

/// Provider-agnostic LLM client.
pub struct LlmClient {
    http: reqwest::Client,
    config: LlmConfig,
}

impl LlmClient {
    /// Create a new LLM client with the given configuration.
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
        }
    }

    /// Create a client from environment variables.
    /// Returns `None` if no API key is configured.
    pub fn from_env() -> Option<Self> {
        LlmConfig::from_env().map(Self::new)
    }

    /// Create a client from environment variables with optional CLI overrides.
    pub fn from_env_with_overrides(
        custom_url: Option<String>,
        custom_model: Option<String>,
    ) -> Option<Self> {
        LlmConfig::from_env_with_overrides(custom_url, custom_model).map(Self::new)
    }

    /// Send a chat completion request and return the response content.
    pub async fn chat(&self, messages: &[Message], temperature: f64) -> Result<String> {
        let request = ChatRequest {
            model: &self.config.model,
            messages,
            temperature,
            response_format: ResponseFormat {
                format_type: "json_object".to_string(),
            },
        };

        let url = format!("{}/chat/completions", self.config.base_url);

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send request to LLM provider")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!("LLM API error (HTTP {}): {}", status, body);
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse LLM response")?;

        chat_response
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .context("No content in LLM response")
    }

    /// Get the model name being used.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Get the base URL being used.
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = Message {
            role: "system".to_string(),
            content: "You are a security researcher.".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("system"));
        assert!(json.contains("security researcher"));
    }

    #[test]
    fn test_config_defaults() {
        // Deterministic test without mutating process environment
        let config = LlmConfig::from_lookup(|_| None, None, None);
        assert!(config.is_none());

        let configured = LlmConfig::from_lookup(
            |k| match k {
                "SKILL_DOCTOR_LLM_KEY" => Some("test-key".to_string()),
                _ => None,
            },
            Some("http://custom-url".to_string()),
            Some("custom-model".to_string()),
        );
        assert!(configured.is_some());
        let c = configured.unwrap();
        assert_eq!(c.api_key, "test-key");
        assert_eq!(c.base_url, "http://custom-url");
        assert_eq!(c.model, "custom-model");
    }
}
