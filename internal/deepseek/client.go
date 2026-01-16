package deepseek

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	defaultBaseURL = "https://api.deepseek.com"
	defaultModel   = "deepseek-chat"
)

type Client struct {
	ApiKey     string
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient() (*Client, error) {
	apiKey := os.Getenv("DEEPSEEK_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("DEEPSEEK_API_KEY environment variable is not set")
	}

	return &Client{
		ApiKey:     apiKey,
		BaseURL:    defaultBaseURL,
		HTTPClient: &http.Client{Timeout: 180 * time.Second}, // Increased for larger payloads
	}, nil
}

type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Id      string `json:"id"`
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

// Summon (Complete) sends a prompt to DeepSeek and returns the "resurrected" answer
func (c *Client) Summon(systemPrompt, userPrompt string) (string, error) {
	reqBody := ChatRequest{
		Model: defaultModel,
		Messages: []Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.7,  // High creativity for "mutations"
		MaxTokens:   8000, // Increased to prevent truncation
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read error body for better debugging
		bodyBytes, _ := json.Marshal(reqBody)
		return "", fmt.Errorf("API request failed with status: %d (payload size: %d bytes)", resp.StatusCode, len(bodyBytes))
	}

	var chatResp ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", err
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}

	return chatResp.Choices[0].Message.Content, nil
}
