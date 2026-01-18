package privacy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MappingFile represents a saved tokenization mapping
type MappingFile struct {
	RunID     string            `json:"run_id"`
	CreatedAt string            `json:"created_at"`
	Salt      string            `json:"salt"`
	Mappings  map[string]string `json:"mappings"`
}

// SaveMapping saves the tokenization mapping to disk
func (t *Tokenizer) SaveMapping(runID string) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Create .necromancer/mappings directory
	mappingDir := filepath.Join(".necromancer", "mappings")
	if err := os.MkdirAll(mappingDir, 0700); err != nil {
		return fmt.Errorf("failed to create mapping directory: %w", err)
	}

	// Create .gitignore in .necromancer directory
	gitignorePath := filepath.Join(".necromancer", ".gitignore")
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		gitignoreContent := "# Ignore all mapping files - they contain sensitive data\nmappings/\n"
		if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0600); err != nil {
			return fmt.Errorf("failed to create .gitignore: %w", err)
		}
	}

	// Create mapping file
	mappingFile := MappingFile{
		RunID:     runID,
		CreatedAt: time.Now().Format(time.RFC3339),
		Salt:      t.salt,
		Mappings:  t.mapping,
	}

	// Write to file
	filename := filepath.Join(mappingDir, fmt.Sprintf("run_%s.json", runID))
	data, err := json.MarshalIndent(mappingFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal mapping: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write mapping file: %w", err)
	}

	return nil
}

// LoadMapping loads a tokenization mapping from disk
func (t *Tokenizer) LoadMapping(runID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	filename := filepath.Join(".necromancer", "mappings", fmt.Sprintf("run_%s.json", runID))

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read mapping file: %w", err)
	}

	var mappingFile MappingFile
	if err := json.Unmarshal(data, &mappingFile); err != nil {
		return fmt.Errorf("failed to unmarshal mapping: %w", err)
	}

	// Restore mappings
	t.salt = mappingFile.Salt
	t.mapping = mappingFile.Mappings

	// Rebuild reverse mapping
	t.reverse = make(map[string]string)
	for real, token := range t.mapping {
		t.reverse[token] = real
	}

	return nil
}

// DeleteMapping removes a mapping file
func DeleteMapping(runID string) error {
	filename := filepath.Join(".necromancer", "mappings", fmt.Sprintf("run_%s.json", runID))
	return os.Remove(filename)
}

// GenerateRunID creates a unique run identifier
func GenerateRunID() string {
	return time.Now().Format("20060102_150405")
}
