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
	Enabled     bool   `json:"enabled,omitempty"`
	AgeRelative string `json:"age,omitempty"`
}

// SanitizedEdge represents a tokenized ACE relationship between entities
type SanitizedEdge struct {
	Source       string `json:"source"`        // tokenized principal SID
	Target       string `json:"target"`        // tokenized target SID/name
	Relationship string `json:"relationship"`  // RightName (GenericAll, WriteDACL, etc.)
	Inherited    bool   `json:"inherited,omitempty"`
}

// DataSummary provides high-level statistics
type DataSummary struct {
	TotalEntities int `json:"total_entities"`
	UserCount     int `json:"user_count"`
	GroupCount    int `json:"group_count"`
	ComputerCount int `json:"computer_count"`
	OUCount       int `json:"ou_count"`
	GPOCount      int `json:"gpo_count"`
	TemplateCount int `json:"template_count"`
	CACount       int `json:"ca_count"`
	EdgeCount     int `json:"edge_count"`
}

// SanitizeBloodHoundData converts raw BloodHound data to fully tokenized format.
// ALL entity names, SIDs, and ACE relationships are replaced with opaque tokens
// before the data leaves this function — nothing real reaches the remote AI.
func SanitizeBloodHoundData(data *bloodhound.BloodHoundData, tokenizer *Tokenizer, maxEntitiesPerType int) *SanitizedData {
	sanitized := &SanitizedData{
		Entities:      []SanitizedEntity{},
		Relationships: []SanitizedEdge{},
	}

	// --- Build a SID → token lookup for fast ACE resolution ---
	// We register every entity SID before processing edges so ACEs can be resolved
	sidToToken := make(map[string]string)

	// Pre-register all SIDs
	for _, u := range data.Users {
		tok := tokenizer.TokenizeUser(u.Properties.Name)
		sidToToken[u.ObjectIdentifier] = tok
	}
	for _, g := range data.Groups {
		tok := tokenizer.TokenizeGroup(g.Properties.Name)
		sidToToken[g.ObjectIdentifier] = tok
	}
	for _, c := range data.Computers {
		tier := detectComputerTier(c)
		tok := tokenizer.TokenizeComputer(c.Properties.Name, tier)
		sidToToken[c.ObjectIdentifier] = tok
	}
	for _, o := range data.OUs {
		tok := tokenizer.TokenizeOU(o.Properties.Name)
		sidToToken[o.ObjectIdentifier] = tok
	}
	for _, g := range data.GPOs {
		tok := tokenizer.TokenizeGPO(g.Properties.Name)
		sidToToken[g.ObjectIdentifier] = tok
	}
	for _, d := range data.Domains {
		tok := tokenizer.TokenizeDomain(d.Properties.Name)
		sidToToken[d.ObjectIdentifier] = tok
	}
	for _, t := range data.CertTemplates {
		tok := tokenizer.TokenizeTemplate(t.Properties.Name)
		sidToToken[t.ObjectIdentifier] = tok
	}
	for _, ca := range data.EnterpriseCAs {
		tok := tokenizer.TokenizeCA(ca.Properties.Name)
		sidToToken[ca.ObjectIdentifier] = tok
	}

	// --- Sanitize Users ---
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
			Enabled:    user.Properties.Enabled,
		}
		if user.Properties.PasswordLastSet > 0 {
			entity.AgeRelative = formatRelativeAge(user.Properties.PasswordLastSet)
		}
		sanitized.Entities = append(sanitized.Entities, entity)
		sanitized.Relationships = append(sanitized.Relationships, tokenizeACEs(user.Aces, sidToToken, tokenizer, tokenizer.TokenizeUser(user.Properties.Name))...)
		userCount++
	}

	// --- Sanitize Groups ---
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
		sanitized.Relationships = append(sanitized.Relationships, tokenizeACEs(group.Aces, sidToToken, tokenizer, tokenizer.TokenizeGroup(group.Properties.Name))...)
		groupCount++
	}

	// --- Sanitize Computers ---
	computerCount := 0
	for _, computer := range data.Computers {
		if computerCount >= maxEntitiesPerType {
			break
		}
		tier := detectComputerTier(computer)
		entity := SanitizedEntity{
			Token:     tokenizer.TokenizeComputer(computer.Properties.Name, tier),
			Type:      "Computer",
			Tier:      tier,
			HighValue: computer.Properties.HighValue,
			Enabled:   computer.Properties.Enabled,
		}
		sanitized.Entities = append(sanitized.Entities, entity)
		sanitized.Relationships = append(sanitized.Relationships, tokenizeACEs(computer.Aces, sidToToken, tokenizer, tokenizer.TokenizeComputer(computer.Properties.Name, tier))...)
		computerCount++
	}

	// --- Sanitize OUs ---
	ouCount := 0
	for _, ou := range data.OUs {
		if ouCount >= maxEntitiesPerType {
			break
		}
		entity := SanitizedEntity{
			Token:     tokenizer.TokenizeOU(ou.Properties.Name),
			Type:      "OU",
			HighValue: ou.Properties.HighValue,
		}
		sanitized.Entities = append(sanitized.Entities, entity)
		sanitized.Relationships = append(sanitized.Relationships, tokenizeACEs(ou.Aces, sidToToken, tokenizer, tokenizer.TokenizeOU(ou.Properties.Name))...)
		ouCount++
	}

	// --- Sanitize GPOs ---
	gpoCount := 0
	for _, gpo := range data.GPOs {
		if gpoCount >= maxEntitiesPerType {
			break
		}
		entity := SanitizedEntity{
			Token:     tokenizer.TokenizeGPO(gpo.Properties.Name),
			Type:      "GPO",
			HighValue: gpo.Properties.HighValue,
		}
		sanitized.Entities = append(sanitized.Entities, entity)
		sanitized.Relationships = append(sanitized.Relationships, tokenizeACEs(gpo.Aces, sidToToken, tokenizer, tokenizer.TokenizeGPO(gpo.Properties.Name))...)
		gpoCount++
	}

	// --- Sanitize Certificate Templates ---
	templateCount := 0
	for _, tmpl := range data.CertTemplates {
		if templateCount >= maxEntitiesPerType {
			break
		}
		entity := SanitizedEntity{
			Token:     tokenizer.TokenizeTemplate(tmpl.Properties.Name),
			Type:      "CertTemplate",
			HighValue: tmpl.Properties.HighValue,
		}
		sanitized.Entities = append(sanitized.Entities, entity)
		sanitized.Relationships = append(sanitized.Relationships, tokenizeACEs(tmpl.Aces, sidToToken, tokenizer, tokenizer.TokenizeTemplate(tmpl.Properties.Name))...)
		templateCount++
	}

	// --- Sanitize Enterprise CAs ---
	caCount := 0
	for _, ca := range data.EnterpriseCAs {
		if caCount >= maxEntitiesPerType {
			break
		}
		entity := SanitizedEntity{
			Token:     tokenizer.TokenizeCA(ca.Properties.Name),
			Type:      "EnterpriseCA",
			HighValue: ca.Properties.HighValue,
		}
		sanitized.Entities = append(sanitized.Entities, entity)
		sanitized.Relationships = append(sanitized.Relationships, tokenizeACEs(ca.Aces, sidToToken, tokenizer, tokenizer.TokenizeCA(ca.Properties.Name))...)
		caCount++
	}

	// --- Build summary ---
	sanitized.Summary = DataSummary{
		TotalEntities: len(sanitized.Entities),
		UserCount:     userCount,
		GroupCount:    groupCount,
		ComputerCount: computerCount,
		OUCount:       ouCount,
		GPOCount:      gpoCount,
		TemplateCount: templateCount,
		CACount:       caCount,
		EdgeCount:     len(sanitized.Relationships),
	}

	return sanitized
}

// detectComputerTier determines the tier of a computer based on its properties.
//
//   - Tier 0: Domain Controllers, PKI/CA systems, high-value assets, or admincount==true
//   - Tier 1: Servers with admincount OR operating systems that look like servers
//   - Tier 2: Workstations and everything else
func detectComputerTier(computer bloodhound.Node) int {
	name := strings.ToLower(computer.Properties.Name)
	os := strings.ToLower(computer.Properties.OperatingSystem)

	// Tier 0: Explicit high-value or DC indicators
	if computer.Properties.HighValue {
		return 0
	}
	if strings.Contains(name, "dc") || strings.Contains(name, "domaincontroller") ||
		strings.Contains(name, "-dc") || strings.HasPrefix(name, "dc-") ||
		strings.Contains(name, "pki") || strings.Contains(name, "adcs") ||
		strings.Contains(name, "ca-") || strings.HasSuffix(name, "-ca") {
		return 0
	}
	if strings.Contains(os, "domain controller") {
		return 0
	}

	// Tier 1: Servers with admin count or server OS
	if computer.Properties.AdminCount {
		return 1
	}
	if strings.Contains(os, "server") {
		return 1
	}
	if strings.Contains(name, "srv") || strings.Contains(name, "server") ||
		strings.Contains(name, "sql") || strings.Contains(name, "exchange") ||
		strings.Contains(name, "mail") || strings.Contains(name, "app") {
		return 1
	}

	// Tier 2: Workstations and everything else
	return 2
}

// tokenizeACEs converts a slice of raw ACEs into tokenized SanitizedEdges.
// All principal SIDs are replaced with their tokens. Unknown SIDs get a SID_ token.
func tokenizeACEs(aces []bloodhound.Ace, sidToToken map[string]string, tokenizer *Tokenizer, targetToken string) []SanitizedEdge {
	edges := make([]SanitizedEdge, 0, len(aces))
	for _, ace := range aces {
		if ace.PrincipalSID == "" || ace.RightName == "" {
			continue
		}

		// Resolve principal SID to its token, or generate a SID_ token
		sourceToken, known := sidToToken[ace.PrincipalSID]
		if !known {
			sourceToken = tokenizer.TokenizeSID(ace.PrincipalSID)
		}

		edges = append(edges, SanitizedEdge{
			Source:       sourceToken,
			Target:       targetToken,
			Relationship: ace.RightName, // control edge name is not sensitive
			Inherited:    ace.IsInherited,
		})
	}
	return edges
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
