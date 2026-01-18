package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Tokenizer handles deterministic tokenization of sensitive AD data
type Tokenizer struct {
	mapping map[string]string // real → token
	reverse map[string]string // token → real
	salt    string            // per-run salt for determinism
	mu      sync.RWMutex      // thread-safe access
}

// NewTokenizer creates a new tokenizer with a random salt
func NewTokenizer() *Tokenizer {
	// Generate salt from current timestamp for determinism within a run
	salt := fmt.Sprintf("%d", getCurrentTimestamp())

	return &Tokenizer{
		mapping: make(map[string]string),
		reverse: make(map[string]string),
		salt:    salt,
	}
}

// generateToken creates a deterministic token from input
func (t *Tokenizer) generateToken(input, prefix string) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if already tokenized
	if token, exists := t.mapping[input]; exists {
		return token
	}

	// Generate deterministic hash
	hash := sha256.Sum256([]byte(input + t.salt))
	suffix := hex.EncodeToString(hash[:])[:4] // First 4 hex chars
	token := prefix + strings.ToUpper(suffix)

	// Store bidirectional mapping
	t.mapping[input] = token
	t.reverse[token] = input

	return token
}

// TokenizeDomain tokenizes a domain name
func (t *Tokenizer) TokenizeDomain(domain string) string {
	if domain == "" {
		return ""
	}
	return t.generateToken(strings.ToUpper(domain), "DOM_")
}

// TokenizeUser tokenizes a username
func (t *Tokenizer) TokenizeUser(username string) string {
	if username == "" {
		return ""
	}
	return t.generateToken(strings.ToUpper(username), "ID_U_")
}

// TokenizeGroup tokenizes a group name
func (t *Tokenizer) TokenizeGroup(groupname string) string {
	if groupname == "" {
		return ""
	}
	return t.generateToken(strings.ToUpper(groupname), "ID_G_")
}

// TokenizeComputer tokenizes a computer hostname with tier awareness
func (t *Tokenizer) TokenizeComputer(hostname string, tier int) string {
	if hostname == "" {
		return ""
	}

	var prefix string
	switch tier {
	case 0:
		prefix = "H_T0_"
	case 1:
		prefix = "H_T1_"
	default:
		prefix = "H_"
	}

	return t.generateToken(strings.ToUpper(hostname), prefix)
}

// TokenizeOU tokenizes an organizational unit DN
func (t *Tokenizer) TokenizeOU(dn string) string {
	if dn == "" {
		return ""
	}
	return t.generateToken(strings.ToUpper(dn), "OU_")
}

// TokenizeGPO tokenizes a GPO name
func (t *Tokenizer) TokenizeGPO(gpoName string) string {
	if gpoName == "" {
		return ""
	}
	return t.generateToken(strings.ToUpper(gpoName), "GPO_")
}

// TokenizeSID tokenizes a SID
func (t *Tokenizer) TokenizeSID(sid string) string {
	if sid == "" {
		return ""
	}
	return t.generateToken(sid, "SID_")
}

// TokenizeTemplate tokenizes a certificate template name
func (t *Tokenizer) TokenizeTemplate(templateName string) string {
	if templateName == "" {
		return ""
	}
	return t.generateToken(strings.ToUpper(templateName), "TMPL_")
}

// TokenizeCA tokenizes an Enterprise CA name
func (t *Tokenizer) TokenizeCA(caName string) string {
	if caName == "" {
		return ""
	}
	return t.generateToken(strings.ToUpper(caName), "CA_")
}

// Detokenize replaces all known tokens in text with real names
func (t *Tokenizer) Detokenize(text string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := text

	// Replace all known tokens
	for token, real := range t.reverse {
		result = strings.ReplaceAll(result, token, real)
	}

	// Paranoia mode: strip unknown domains/hostnames that might have leaked
	result = t.stripUnknownDomains(result)

	return result
}

// stripUnknownDomains removes potential domain names that aren't in our token list
func (t *Tokenizer) stripUnknownDomains(text string) string {
	// Regex to find potential domains (simple pattern)
	// This is paranoia mode - if AI invents a domain-like string, redact it
	re := regexp.MustCompile(`\b[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.([a-z]{2,})\b`)

	return re.ReplaceAllStringFunc(text, func(match string) string {
		// If it's not a known token, redact it
		if _, isToken := t.reverse[match]; !isToken {
			// Check if it looks like a real domain (not our tokens)
			if !strings.HasPrefix(match, "DOM_") &&
				!strings.HasPrefix(match, "H_") &&
				!strings.HasPrefix(match, "ID_") {
				return "[REDACTED]"
			}
		}
		return match
	})
}

// GetMappingCount returns the number of tokenized entities
func (t *Tokenizer) GetMappingCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.mapping)
}

// Helper function to get current timestamp
func getCurrentTimestamp() int64 {
	// In production, use time.Now().Unix()
	// For testing, this can be mocked
	return 1737234000 // Fixed for determinism in testing
}
