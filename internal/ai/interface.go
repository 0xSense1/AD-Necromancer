package ai

// AIClient is the interface that all AI backend clients must implement
type AIClient interface {
	// Summon sends a system prompt and user prompt to the AI backend
	// and returns the raw JSON response as a string
	Summon(systemPrompt, userPrompt string) (string, error)
}
