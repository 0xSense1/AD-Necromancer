package necromancy

import (
	"encoding/json"
	"fmt"
	"strings"

	"ad-necromancer/internal/ai"
	"ad-necromancer/internal/bloodhound"
	"ad-necromancer/internal/privacy"
	"ad-necromancer/internal/prompts"
)

type Engine struct {
	BHLoader     *bloodhound.Loader
	AIClient     ai.AIClient
	Tokenizer    *privacy.Tokenizer
	CloakEnabled bool
}

type ZombiePath struct {
	Title             string   `json:"Title"`
	Artifact          string   `json:"Artifact"`
	Category          string   `json:"Category"`
	Reasoning         string   `json:"Reasoning"`
	Mutation          string   `json:"Mutation"`
	ResurrectedChain  string   `json:"ResurrectedChain"` // Renamed from ExploitChain
	ExecutionVectors  []string `json:"ExecutionVectors"` // Renamed from Commands
	VisualPath        string   `json:"VisualPath"`       // ASCII graph visualization
	HumanBlindSpot    []string `json:"HumanBlindSpot"`   // NEW: Human process failures
	Impact            []string `json:"Impact"`           // NEW: Impact analysis
	WhyThisExists     string   `json:"WhyThisExists"`    // NEW: Root cause
	Probability       string   `json:"Probability"`
	RiskJustification string   `json:"RiskJustification"`
	DetectionRules    []string `json:"DetectionRules"`
	Mitigation        string   `json:"Mitigation"`

	// Entity details
	EntityName   string `json:"EntityName"`   // NEW: e.g., "svc_backup_legacy"
	EntityType   string `json:"EntityType"`   // NEW: e.g., "Service Account"
	EntityStatus string `json:"EntityStatus"` // NEW: e.g., "Abandoned (892 days)"
	EntityOrigin string `json:"EntityOrigin"` // NEW: e.g., "Decommissioned system"

	// MITRE ATT&CK mapping (1-3 techniques max, output annotation only)
	MitreAttack []string `json:"MitreAttack,omitempty"` // e.g., ["T1484.001", "T1558.003"]

	// Legacy fields for backward compatibility
	Description  string   `json:"Description,omitempty"`
	Command      string   `json:"Command,omitempty"`
	ExploitChain string   `json:"ExploitChain,omitempty"`
	Commands     []string `json:"Commands,omitempty"`
}

// NewEngine creates a new necromancy engine
func NewEngine(loader *bloodhound.Loader, client ai.AIClient) *Engine {
	return &Engine{
		BHLoader: loader,
		AIClient: client,
	}
}

// Resurrect takes a subset of nodes and asks the LLM to find attack paths
func (e *Engine) Resurrect() ([]ZombiePath, error) {
	return e.ResurrectWithSampleSize(20)
}

// ResurrectWithSampleSize allows configurable sample size per entity type
func (e *Engine) ResurrectWithSampleSize(maxEntitiesPerType int) ([]ZombiePath, error) {
	// 1. Prepare Data Snippet with INTELLIGENT SAMPLING
	// To avoid API 400 errors from payload size, we sample strategically:
	// - Prioritize high-value targets (admincount=true, highvalue=true)
	// - Limit to reasonable sizes while maintaining diversity

	var dataBytes []byte
	var err error

	// If Privacy Cloak is enabled, use sanitized tokenized data
	if e.CloakEnabled && e.Tokenizer != nil {
		// Create sanitized, tokenized data structure
		sanitized := privacy.SanitizeBloodHoundData(&e.BHLoader.Data, e.Tokenizer, maxEntitiesPerType)

		dataBytes, err = json.MarshalIndent(sanitized, "", "  ")
		if err != nil {
			return nil, err
		}

		fmt.Printf("\n[🔒] Privacy Cloak: %d entities tokenized (%d tokens generated)\n",
			sanitized.Summary.TotalEntities, e.Tokenizer.GetMappingCount())
	} else {
		// Original behavior: send raw data
		snippet := make(map[string]interface{})

		// Sample users intelligently (prioritize high-value)
		users := sampleNodes(e.BHLoader.Data.Users, maxEntitiesPerType)
		snippet["users"] = users

		// Sample groups intelligently
		groups := sampleNodes(e.BHLoader.Data.Groups, maxEntitiesPerType)
		snippet["groups"] = groups

		// Sample computers intelligently
		computers := sampleNodes(e.BHLoader.Data.Computers, maxEntitiesPerType)
		snippet["computers"] = computers

		// Include all GPOs (usually small number)
		snippet["gpos"] = e.BHLoader.Data.GPOs

		// Include all OUs (usually small number)
		snippet["ous"] = e.BHLoader.Data.OUs

		// Sample CertTemplates (respects --sample-size flag)
		certTemplates := sampleNodes(e.BHLoader.Data.CertTemplates, maxEntitiesPerType)
		snippet["certtemplates"] = certTemplates

		// Sample EnterpriseCAs (respects --sample-size flag)
		enterpriseCAs := sampleNodes(e.BHLoader.Data.EnterpriseCAs, maxEntitiesPerType)
		snippet["enterprisecas"] = enterpriseCAs

		fmt.Printf("\n[*] Analysis Scope (Sampled): %d Users, %d Groups, %d Computers, %d CertTemplates, %d EnterpriseCAs\n",
			len(users), len(groups), len(computers), len(certTemplates), len(enterpriseCAs))

		dataBytes, err = json.MarshalIndent(snippet, "", "  ")
		if err != nil {
			return nil, err
		}
	}

	// 2. Build User Prompt
	userPrompt := fmt.Sprintf(`You are analyzing BloodHound data for an Active Directory environment.

ENVIRONMENT SNAPSHOT:
- %d Users
- %d Groups  
- %d Computers
- %d Domains
- %d GPOs
- %d OUs

Your mission: Discover FORGOTTEN CONTROL PATHS that humans have lost track of.

Focus on:
1. ABANDONED IDENTITIES (orphaned service accounts, test users, forgotten admins)
2. FORGOTTEN CONTROL EDGES (WriteDACL, GenericAll, AddMember on critical objects)
3. CERTIFICATE TEMPLATE ABUSE (ESC1-ESC13 attacks, enrollment rights)
4. SID HISTORY EXPLOITATION (orphaned SIDs from old trusts/migrations)
5. LATERAL MOVEMENT OPPORTUNITIES (local admin rights, session hijacking)
6. PRIVILEGE ESCALATION PATHS (combining weak permissions into DA)
7. GPO ABUSE (weak GPO permissions, GPO-based persistence)

Requirements:
- Use ACTUAL data from the JSON below (real SIDs, usernames, properties)
- Provide COMPLETE exploit chains with copy-paste ready commands
- Include DETECTION rules for each attack (Splunk/Sentinel/CrowdStrike)
- Be CREATIVE with mutations (what-if scenarios)
- Assign JUSTIFIED risk scores (Critical/High/Medium/Low)

═══════════════════════════════════════════════════════════════════════════════
BLOODHOUND DATA (JSON)
═══════════════════════════════════════════════════════════════════════════════

%s

═══════════════════════════════════════════════════════════════════════════════
BEGIN RESURRECTION ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

Output your findings as a JSON array of ZombiePath objects, SORTED BY RISK (Critical/High first). Be thorough, technical, and creative.`,
		len(e.BHLoader.Data.Users),
		len(e.BHLoader.Data.Groups),
		len(e.BHLoader.Data.Computers),
		len(e.BHLoader.Data.Domains),
		len(e.BHLoader.Data.GPOs),
		len(e.BHLoader.Data.OUs),
		string(dataBytes))

	// 3. Summon the AI
	response, err := e.AIClient.Summon(prompts.NecromancerSystemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	// 3.5. De-tokenize response if Privacy Cloak was enabled
	if e.CloakEnabled && e.Tokenizer != nil {
		response = e.Tokenizer.Detokenize(response)
	}

	// 4. Parse Response (handling potential markdown code blocks and formatting issues)
	cleanJson := strings.TrimSpace(response)
	cleanJson = strings.TrimPrefix(cleanJson, "```json")
	cleanJson = strings.TrimPrefix(cleanJson, "```")
	cleanJson = strings.TrimSuffix(cleanJson, "```")
	cleanJson = strings.TrimSpace(cleanJson)

	// Try to fix common JSON issues from LLMs
	cleanJson = fixLLMJson(cleanJson)

	var paths []ZombiePath
	if err := json.Unmarshal([]byte(cleanJson), &paths); err != nil {
		// If parsing fails, return an error instead of debug output
		return nil, fmt.Errorf("failed to parse LLM response as JSON: %w", err)
	}

	// Sort paths by risk level (Critical > High > Medium > Low)
	sortByRisk(paths)

	return paths, nil
}

// sortByRisk sorts zombie paths by risk level in descending order
func sortByRisk(paths []ZombiePath) {
	riskOrder := map[string]int{
		"Critical": 4,
		"High":     3,
		"Medium":   2,
		"Low":      1,
		"Unknown":  0,
	}

	// Simple bubble sort (good enough for small arrays)
	for i := 0; i < len(paths)-1; i++ {
		for j := 0; j < len(paths)-i-1; j++ {
			risk1 := riskOrder[paths[j].Probability]
			risk2 := riskOrder[paths[j+1].Probability]
			if risk1 < risk2 {
				paths[j], paths[j+1] = paths[j+1], paths[j]
			}
		}
	}
}

// sampleNodes intelligently samples nodes, prioritizing control-based identities
func sampleNodes(nodes []bloodhound.Node, maxCount int) []bloodhound.Node {
	if len(nodes) <= maxCount {
		return nodes
	}

	// Categorize nodes by priority
	var controlBased []bloodhound.Node  // Has interesting control edges
	var highValue []bloodhound.Node     // AdminCount/HighValue but not built-in admin
	var regular []bloodhound.Node       // Everything else
	var builtInAdmins []bloodhound.Node // Built-in Administrator (lowest priority)

	for _, node := range nodes {
		name := strings.ToLower(node.Properties.Name)

		// Deprioritize built-in Administrator
		if strings.Contains(name, "administrator@") && !strings.Contains(name, "domain admins") {
			builtInAdmins = append(builtInAdmins, node)
			continue
		}

		// Prioritize nodes with control-indicating properties
		// Look for service accounts, delegation, or control-related names
		hasControlIndicators := strings.Contains(name, "svc_") ||
			strings.Contains(name, "service") ||
			strings.Contains(name, "admin") ||
			strings.Contains(name, "delegate") ||
			strings.Contains(name, "gpo") ||
			node.Properties.Enabled == false // Disabled but still has privileges

		if hasControlIndicators {
			controlBased = append(controlBased, node)
		} else if node.Properties.AdminCount || node.Properties.HighValue {
			highValue = append(highValue, node)
		} else {
			regular = append(regular, node)
		}
	}

	// Build result with priority order
	result := make([]bloodhound.Node, 0, maxCount)

	// 1. Control-based identities first
	for _, node := range controlBased {
		if len(result) >= maxCount {
			break
		}
		result = append(result, node)
	}

	// 2. High-value nodes (but not built-in admins)
	for _, node := range highValue {
		if len(result) >= maxCount {
			break
		}
		result = append(result, node)
	}

	// 3. Regular nodes
	for _, node := range regular {
		if len(result) >= maxCount {
			break
		}
		result = append(result, node)
	}

	// 4. Built-in admins (lowest priority, only if we have room)
	for _, node := range builtInAdmins {
		if len(result) >= maxCount {
			break
		}
		result = append(result, node)
	}

	return result
}

// fixLLMJson attempts to fix common JSON formatting issues from LLMs
func fixLLMJson(jsonStr string) string {
	// This is a simple approach - just return as-is for now
	// The prompt instructions should prevent most issues
	// If needed, we can add more sophisticated cleaning later
	return jsonStr
}

// truncate returns a truncated version of the string if it exceeds maxLen
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
