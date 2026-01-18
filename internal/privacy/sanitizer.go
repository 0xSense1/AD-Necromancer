package privacy

import (
	"fmt"
	"strings"
	"time"

	"ad-necromancer/internal/bloodhound"
)

// SanitizedData represents tokenized BloodHound data safe for remote AI
type SanitizedData struct {
	Entities      []SanitizedEntity `json:"entities"`
	Relationships []SanitizedEdge   `json:"relationships"`
	Summary       DataSummary       `json:"summary"`
}

// SanitizedEntity represents a tokenized AD entity
type SanitizedEntity struct {
	Token       string `json:"token"`
	Type        string `json:"type"`
	Tier        int    `json:"tier,omitempty"`
	HighValue   bool   `json:"highvalue,omitempty"`
	AdminCount  bool   `json:"admincount,omitempty"`
	AgeRelative string `json:"age,omitempty"`
}

// SanitizedEdge represents a relationship between entities
type SanitizedEdge struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	Relationship string `json:"relationship"`
}

// DataSummary provides high-level statistics
type DataSummary struct {
	TotalEntities int `json:"total_entities"`
	UserCount     int `json:"user_count"`
	GroupCount    int `json:"group_count"`
	ComputerCount int `json:"computer_count"`
	EdgeCount     int `json:"edge_count"`
}

// SanitizeBloodHoundData converts raw BloodHound data to tokenized format
func SanitizeBloodHoundData(data *bloodhound.BloodHoundData, tokenizer *Tokenizer, maxEntitiesPerType int) *SanitizedData {
	sanitized := &SanitizedData{
		Entities:      []SanitizedEntity{},
		Relationships: []SanitizedEdge{},
	}

	// Sanitize users
	userCount := 0
	for _, user := range data.Users {
		if userCount >= maxEntitiesPerType {
			break
		}

		entity := SanitizedEntity{
			Token:      tokenizer.TokenizeUser(user.Properties.Name),
			Type:       "User",
			AdminCount: user.Properties.AdminCount,
			HighValue:  user.Properties.HighValue,
		}

		// Convert timestamp to relative age
		if user.Properties.PasswordLastSet > 0 {
			entity.AgeRelative = formatRelativeAge(user.Properties.PasswordLastSet)
		}

		sanitized.Entities = append(sanitized.Entities, entity)
		userCount++
	}

	// Sanitize groups
	groupCount := 0
	for _, group := range data.Groups {
		if groupCount >= maxEntitiesPerType {
			break
		}

		entity := SanitizedEntity{
			Token:      tokenizer.TokenizeGroup(group.Properties.Name),
			Type:       "Group",
			AdminCount: group.Properties.AdminCount,
			HighValue:  group.Properties.HighValue,
		}

		sanitized.Entities = append(sanitized.Entities, entity)
		groupCount++
	}

	// Sanitize computers
	computerCount := 0
	for _, computer := range data.Computers {
		if computerCount >= maxEntitiesPerType {
			break
		}

		tier := 0 // Default tier - would need to be determined from properties

		entity := SanitizedEntity{
			Token:     tokenizer.TokenizeComputer(computer.Properties.Name, tier),
			Type:      "Computer",
			Tier:      tier,
			HighValue: computer.Properties.HighValue,
		}

		sanitized.Entities = append(sanitized.Entities, entity)
		computerCount++
	}

	// Build summary
	sanitized.Summary = DataSummary{
		TotalEntities: len(sanitized.Entities),
		UserCount:     userCount,
		GroupCount:    groupCount,
		ComputerCount: computerCount,
		EdgeCount:     0, // Will be populated if we add edge sanitization
	}

	return sanitized
}

// TokenizeJSON tokenizes all sensitive fields in a JSON string
func (t *Tokenizer) TokenizeJSON(jsonStr string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := jsonStr

	// Replace all real names with tokens
	for real, token := range t.mapping {
		result = strings.ReplaceAll(result, real, token)
	}

	return result
}

// Helper functions

func formatRelativeAge(epochSeconds int64) string {
	if epochSeconds == 0 {
		return "never"
	}

	now := time.Now().Unix()
	diff := now - epochSeconds

	if diff < 0 {
		return "future"
	}

	days := diff / 86400

	if days == 0 {
		return "today"
	} else if days == 1 {
		return "~1 day"
	} else if days < 30 {
		return fmt.Sprintf("~%d days", days)
	} else if days < 365 {
		months := days / 30
		return fmt.Sprintf("~%d months", months)
	} else {
		years := days / 365
		return fmt.Sprintf("~%d years", years)
	}
}
