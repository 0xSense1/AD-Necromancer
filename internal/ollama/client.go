package ollama

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	defaultEndpoint = "http://localhost:11434"
	defaultModel    = "llama3"
)

type Client struct {
	Endpoint string
	Model    string
}

type GenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type GenerateResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// NewClient creates a new Ollama client
func NewClient() (*Client, error) {
	endpoint := os.Getenv("OLLAMA_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = defaultModel
	}

	return &Client{
		Endpoint: endpoint,
		Model:    model,
	}, nil
}

// Summon implements the AIClient interface
func (c *Client) Summon(systemPrompt, userPrompt string) (string, error) {
	// Combine system and user prompts for Ollama
	combinedPrompt := fmt.Sprintf("%s\n\n%s", systemPrompt, userPrompt)

	reqBody := GenerateRequest{
		Model:  c.Model,
		Prompt: combinedPrompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(
		c.Endpoint+"/api/generate",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to call Ollama API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Ollama API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Response, nil
}
