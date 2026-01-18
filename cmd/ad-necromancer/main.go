package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"ad-necromancer/internal/ai"
	"ad-necromancer/internal/bloodhound"
	"ad-necromancer/internal/claude"
	"ad-necromancer/internal/deepseek"
	"ad-necromancer/internal/gemini"
	"ad-necromancer/internal/necromancy"
	"ad-necromancer/internal/ollama"
	"ad-necromancer/internal/openai"
	"ad-necromancer/internal/privacy"
)

// ANSI Color Codes for the "Ritual" theme
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorOrange = "\033[38;5;208m"
	ColorBold   = "\033[1m"
)

func main() {
	var dataDir string
	var sampleSize int
	var onPremise bool
	var useOpenAI bool
	var useGemini bool
	var useClaude bool
	var noPrivacyCloak bool
	var saveMapping bool

	flag.StringVar(&dataDir, "data", "", "Path to directory containing BloodHound JSON files")
	flag.IntVar(&sampleSize, "sample-size", 20, "Max entities per type to send to LLM (users, groups, computers)")
	flag.BoolVar(&onPremise, "on-premise", false, "Use local Ollama backend")
	flag.BoolVar(&useOpenAI, "openai", false, "Use OpenAI backend")
	flag.BoolVar(&useGemini, "gemini", false, "Use Google Gemini backend")
	flag.BoolVar(&useClaude, "claude", false, "Use Anthropic Claude backend")
	flag.BoolVar(&noPrivacyCloak, "no-privacy-cloak", false, "Disable privacy tokenization (send real data to AI)")
	flag.BoolVar(&saveMapping, "save-mapping", false, "Save tokenization mapping to disk")
	flag.Parse()

	printBanner()

	if dataDir == "" {
		log.Fatal(ColorRed + "[!] You must provide the location of the graveyard (--data <path/to/json>)" + ColorReset)
	}

	// 1. Ingest Data
	fmt.Println(ColorCyan + "\n[*] Exhuming artifacts from the directory..." + ColorReset)
	loader := bloodhound.NewLoader()
	if err := loader.LoadFromDirectory(dataDir); err != nil {
		log.Fatalf(ColorRed+"[!] Failed to load data: %v"+ColorReset, err)
	}
	fmt.Printf(ColorGreen+"[+] Loaded: %d Users, %d Groups, %d Computers, %d Domains, %d GPOs, %d OUs, %d CertTemplates, %d EnterpriseCAs\n"+ColorReset,
		len(loader.Data.Users), len(loader.Data.Groups), len(loader.Data.Computers),
		len(loader.Data.Domains), len(loader.Data.GPOs), len(loader.Data.OUs),
		len(loader.Data.CertTemplates), len(loader.Data.EnterpriseCAs))

	// 2. Initialize AI Backend
	var client ai.AIClient
	var err error

	// Check for flag conflicts
	flagCount := 0
	if onPremise {
		flagCount++
	}
	if useOpenAI {
		flagCount++
	}
	if useGemini {
		flagCount++
	}
	if useClaude {
		flagCount++
	}

	if flagCount > 1 {
		fmt.Println(ColorYellow + "[!] Multiple AI backends specified. Using priority: Ollama > Claude > Gemini > OpenAI > DeepSeek" + ColorReset)
	}

	// Select backend based on flags (priority order)
	if onPremise {
		fmt.Println(ColorCyan + "[*] Using Ollama (on-premise) backend..." + ColorReset)
		client, err = ollama.NewClient()
	} else if useClaude {
		fmt.Println(ColorCyan + "[*] Using Anthropic Claude backend..." + ColorReset)
		client, err = claude.NewClient()
	} else if useGemini {
		fmt.Println(ColorCyan + "[*] Using Google Gemini backend..." + ColorReset)
		client, err = gemini.NewClient()
	} else if useOpenAI {
		fmt.Println(ColorCyan + "[*] Using OpenAI backend..." + ColorReset)
		client, err = openai.NewClient()
	} else {
		fmt.Println(ColorCyan + "[*] Using DeepSeek backend (default)..." + ColorReset)
		client, err = deepseek.NewClient()
	}

	if err != nil {
		log.Fatalf(ColorRed+"[!] The connection to the void failed: %v"+ColorReset, err)
	}

	// 2.5. Initialize Privacy Cloak
	var tokenizer *privacy.Tokenizer
	var cloakEnabled bool
	var runID string

	// Determine if Privacy Cloak should be enabled
	// Default: ON for remote AI (DeepSeek/OpenAI), OFF for on-premise (Ollama)
	if noPrivacyCloak {
		cloakEnabled = false
	} else if onPremise {
		cloakEnabled = false // On-premise = data stays local, no need for cloak
	} else {
		cloakEnabled = true // Remote AI = enable cloak by default
	}

	if cloakEnabled {
		tokenizer = privacy.NewTokenizer()
		runID = privacy.GenerateRunID()
		fmt.Println(ColorGreen + "[🔒] Privacy Cloak: ENABLED (tokenized remote AI)" + ColorReset)
	} else {
		if onPremise {
			fmt.Println(ColorCyan + "[*] Privacy Cloak: DISABLED (on-premise AI)" + ColorReset)
		} else {
			fmt.Println(ColorYellow + "[!] Privacy Cloak: DISABLED (sending real data to remote AI)" + ColorReset)
		}
	}

	// 3. Begin Ritual
	fmt.Println(ColorPurple + "\n[*] Disturbing dormant identities..." + ColorReset)
	fmt.Println(ColorPurple + "[*] Listening for forgotten control..." + ColorReset)
	fmt.Println(ColorPurple + "[*] Resurrecting dead privileges..." + ColorReset)
	fmt.Println(ColorCyan + "[*] Using intelligent sampling (prioritizing high-value targets)..." + ColorReset)
	fmt.Println()

	engine := necromancy.NewEngine(loader, client)
	engine.Tokenizer = tokenizer
	engine.CloakEnabled = cloakEnabled

	paths, err := engine.ResurrectWithSampleSize(sampleSize)
	if err != nil {
		log.Fatalf(ColorRed+"[!] The ritual was interrupted: %v"+ColorReset, err)
	}

	// 4. Reveal Undead Paths
	fmt.Println()

	// Count risks for summary
	riskCounts := make(map[string]int)

	for _, p := range paths {
		// Determine color based on risk level
		riskColor := ColorGreen
		riskIcon := "ℹ️"
		switch p.Probability {
		case "Critical":
			riskColor = ColorRed
			riskIcon = "CRITICAL"
		case "High":
			riskColor = ColorOrange
			riskIcon = "HIGH"
		case "Medium":
			riskColor = ColorYellow
			riskIcon = "MEDIUM"
		case "Low":
			riskColor = ColorGreen
			riskIcon = "LOW"
		}
		riskCounts[p.Probability]++

		// Print dramatic header
		fmt.Println(ColorRed + "╔══════════════════════════════════════════════════════════════════════════════╗" + ColorReset)
		fmt.Printf(ColorRed+"║%s☠ UNDEAD CONTROL PATH RESURRECTED — %s%s%-*s%s║\n"+ColorReset,
			" ", riskColor, riskIcon, 48-len(riskIcon), " ", ColorRed)
		fmt.Println(ColorRed + "╚══════════════════════════════════════════════════════════════════════════════╝" + ColorReset)
		fmt.Println()

		// [ENTITY] Section
		if p.EntityName != "" || p.EntityType != "" {
			fmt.Println(ColorCyan + "[ENTITY]" + ColorReset)
			if p.EntityName != "" {
				fmt.Printf("  Name   : %s%s%s\n", ColorPurple, p.EntityName, ColorReset)
			}
			if p.EntityType != "" {
				fmt.Printf("  Type   : %s\n", p.EntityType)
			}
			if p.EntityStatus != "" {
				fmt.Printf("  Status : %s%s%s\n", ColorRed, p.EntityStatus, ColorReset)
			}
			if p.EntityOrigin != "" {
				fmt.Printf("  Origin : %s\n", p.EntityOrigin)
			}
			fmt.Println()
		}

		// [NECROMANCY ANALYSIS] Section
		if p.Reasoning != "" {
			fmt.Println(ColorCyan + "[NECROMANCY ANALYSIS]" + ColorReset)
			// Split reasoning into bullet points if it contains multiple sentences
			reasoningLines := splitIntoBullets(p.Reasoning)
			for _, line := range reasoningLines {
				fmt.Printf("  ▸ %s\n", line)
			}
			fmt.Println()
		}

		// [UNDEAD CONTROL PATH] Section - Visual Graph
		if p.VisualPath != "" {
			fmt.Println(ColorCyan + "[UNDEAD CONTROL PATH]" + ColorReset)
			fmt.Println()
			fmt.Println(p.VisualPath)
			fmt.Println()
		}

		// [HUMAN BLIND SPOT] Section
		if len(p.HumanBlindSpot) > 0 {
			fmt.Println(ColorYellow + "[HUMAN BLIND SPOT]" + ColorReset)
			for _, blindspot := range p.HumanBlindSpot {
				fmt.Printf("  ▸ %s\n", blindspot)
			}
			fmt.Println()
		}

		// [IMPACT] Section
		if len(p.Impact) > 0 {
			fmt.Println(ColorRed + "[IMPACT]" + ColorReset)
			for _, impact := range p.Impact {
				fmt.Printf("  %s\n", impact)
			}
			fmt.Println()
		}

		// [WHY THIS EXISTS] Section
		if p.WhyThisExists != "" {
			fmt.Println(ColorPurple + "[WHY THIS EXISTS]" + ColorReset)
			fmt.Printf("  %s%s%s\n", ColorBold, p.WhyThisExists, ColorReset)
			fmt.Println()
		}

		// [EXECUTION VECTORS] Section (if present, but de-emphasized)
		if len(p.ExecutionVectors) > 0 {
			fmt.Println(ColorCyan + "[EXECUTION VECTORS]" + ColorReset)
			for _, vector := range p.ExecutionVectors {
				fmt.Printf("  • %s\n", vector)
			}
			fmt.Println()
		}

		// [DETECTION] Section
		if len(p.DetectionRules) > 0 {
			fmt.Println(ColorGreen + "[DETECTION RULES]" + ColorReset)
			for _, rule := range p.DetectionRules {
				fmt.Printf("  • %s\n", rule)
			}
			fmt.Println()
		}

		// [MITIGATION] Section
		if p.Mitigation != "" {
			fmt.Println(ColorGreen + "[MITIGATION]" + ColorReset)
			fmt.Printf("  %s\n", p.Mitigation)
			fmt.Println()
		}

		// [MITRE ATT&CK MAPPING] Section (minimal, at the end)
		if len(p.MitreAttack) > 0 {
			fmt.Println(ColorCyan + "[MITRE ATT&CK MAPPING]" + ColorReset)
			for _, technique := range p.MitreAttack {
				fmt.Printf("  ▸ %s\n", technique)
			}
			fmt.Println()
		}

		// Legacy fallback support
		if p.ResurrectedChain != "" {
			fmt.Println(ColorRed + "[RESURRECTED CHAIN]" + ColorReset)
			fmt.Printf("  %s\n", p.ResurrectedChain)
			fmt.Println()
		} else if p.ExploitChain != "" {
			fmt.Println(ColorRed + "[RESURRECTED CHAIN]" + ColorReset)
			fmt.Printf("  %s\n", p.ExploitChain)
			fmt.Println()
		}

		fmt.Println(ColorCyan + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + ColorReset)
		fmt.Println()
	}

	// Print summary
	fmt.Println(ColorPurple + "╔══════════════════════════════════════════════════════════════════════════════╗" + ColorReset)
	fmt.Println(ColorPurple + "║                           RESURRECTION COMPLETE                              ║" + ColorReset)
	fmt.Println(ColorPurple + "╚══════════════════════════════════════════════════════════════════════════════╝" + ColorReset)
	fmt.Println()

	fmt.Printf(ColorGreen+"[✓] Total Undead Paths Discovered: %d\n\n"+ColorReset, len(paths))

	// Show risk breakdown
	hasHighRisk := false
	if riskCounts["Critical"] > 0 {
		fmt.Println(ColorRed + "    ╔══════════════════════════════════════════════════════════════════════════╗" + ColorReset)
		fmt.Printf(ColorRed+"    ║  🔴 CRITICAL RISK: %d path(s) - IMMEDIATE ACTION REQUIRED!              ║\n"+ColorReset, riskCounts["Critical"])
		fmt.Println(ColorRed + "    ╚══════════════════════════════════════════════════════════════════════════╝" + ColorReset)
		hasHighRisk = true
	}
	if riskCounts["High"] > 0 {
		fmt.Printf(ColorOrange+"    🟠 High Risk: %d path(s) - Prioritize remediation\n"+ColorReset, riskCounts["High"])
		hasHighRisk = true
	}
	if riskCounts["Medium"] > 0 {
		fmt.Printf(ColorYellow+"    🟡 Medium Risk: %d path(s) - Schedule for review\n"+ColorReset, riskCounts["Medium"])
	}
	if riskCounts["Low"] > 0 {
		fmt.Printf(ColorGreen+"    🟢 Low Risk: %d path(s) - Monitor and track\n"+ColorReset, riskCounts["Low"])
	}

	fmt.Println()
	if hasHighRisk {
		fmt.Println(ColorRed + "    ⚠️  WARNING: Critical/High risk findings detected!" + ColorReset)
		fmt.Println(ColorRed + "    ⚠️  These forgotten identities could lead to FULL DOMAIN COMPROMISE!" + ColorReset)
		fmt.Println()
	}

	fmt.Println(ColorPurple + "    💀 The dead have spoken. Will you listen?" + ColorReset)
	fmt.Println()

	// 5. Save mapping if requested
	if saveMapping && cloakEnabled && tokenizer != nil {
		if err := tokenizer.SaveMapping(runID); err != nil {
			fmt.Printf(ColorYellow+"[!] Failed to save mapping: %v\n"+ColorReset, err)
		} else {
			fmt.Printf(ColorGreen+"[✓] Mapping saved to .necromancer/mappings/run_%s.json\n"+ColorReset, runID)
			fmt.Println(ColorYellow + "[!] WARNING: Mapping file contains sensitive data. Protect it like credentials." + ColorReset)
		}
	}
}

func printBanner() {
	banner := `
    ___    ____  _   __                                                    
   /   |  / __ \/ | / /__  ______________  ____ ___  ____ _____  ________  _____
  / /| | / / / /  |/ / _ \/ ___/ ___/ __ \/ __  __ \/ __  / __ \/ ___/ _ \/ ___/
 / ___ |/ /_/ / /|  /  __/ /__/ /  / /_/ / / / / / / /_/ / / / / /__/  __/ /    
/_/  |_/_____/_/ |_/\___/\___/_/   \____/_/ /_/ /_/\__,_/_/ /_/\___/\___/_/     
                                                                                
             "Humans forget. Directories do not."
`
	fmt.Println(ColorRed + banner + ColorReset)
}

// splitIntoBullets splits text into bullet points (by sentence or newline)
func splitIntoBullets(text string) []string {
	// First try splitting by newlines
	if strings.Contains(text, "\n") {
		lines := strings.Split(text, "\n")
		var result []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				result = append(result, line)
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	// Otherwise split by sentences
	sentences := strings.Split(text, ". ")
	var result []string
	for i, sentence := range sentences {
		sentence = strings.TrimSpace(sentence)
		if sentence != "" {
			// Add period back if not last sentence
			if i < len(sentences)-1 && !strings.HasSuffix(sentence, ".") {
				sentence += "."
			}
			result = append(result, sentence)
		}
	}

	if len(result) == 0 {
		return []string{text}
	}
	return result
}
