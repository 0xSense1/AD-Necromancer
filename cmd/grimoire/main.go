// Package main — The Grimoire: AD-Necromancer v2 C2 server.
// Serves an embedded gothic UI, receives encrypted agent uploads,
// parses BloodHound JSON, builds a token map, and proxies AI requests to
// any supported provider: Claude, OpenAI, DeepSeek, Gemini, or Ollama.
//
// NOTE: The AI provider logic below (callClaude, callOpenAICompat, callGemini)
// is intentionally inlined here rather than delegating to internal/claude etc.
// Those packages implement the single-turn ai.AIClient Summon(sys, user) interface,
// but the Grimoire needs multi-turn chat with a []chatMessage history.
// The two interfaces are fundamentally different; inlining avoids a forced abstraction.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ad-necromancer/internal/crypto"
	"golang.org/x/crypto/bcrypt"
)

// ── Embedded UI files ─────────────────────────────────────────────────────────

//go:embed web/index.html
var indexHTML []byte

//go:embed web/login.html
var loginHTML []byte

// ── Auth types ────────────────────────────────────────────────────────────────

type Credentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // bcrypt hash
}

type sessionData struct {
	Username  string
	ExpiresAt time.Time
}

type loginAttempt struct {
	Count       int
	LockedUntil time.Time
}

const (
	credsPath        = "grimoire_creds.json"
	aiCfgPath        = "grimoire_ai.json"
	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
	sessionDuration  = 24 * time.Hour
)

var (
	creds      *Credentials
	sessions   = make(map[string]sessionData)
	sessionsMu sync.Mutex

	loginLimiter = make(map[string]*loginAttempt)
	limiterMu    sync.Mutex
)

// ── AI config ─────────────────────────────────────────────────────────────────

type AIConfig struct {
	Provider string `json:"provider"` // claude | openai | deepseek | gemini | ollama
	APIKey   string `json:"api_key"`
	Model    string `json:"model"`
	Endpoint string `json:"endpoint"` // for ollama: base URL
}

// Unified internal message type (matches OpenAI/Claude format)
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

var (
	aiCfg   AIConfig
	aiCfgMu sync.RWMutex
)

// ── Graph types ───────────────────────────────────────────────────────────────

type GraphNode struct {
	ID         string            `json:"id"`
	Label      string            `json:"label"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties,omitempty"`
}

type GraphEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
}

type GraphData struct {
	Nodes           []GraphNode       `json:"nodes"`
	Edges           []GraphEdge       `json:"edges"`
	TokenMap        map[string]string `json:"tokenMap"`
	ReverseTokenMap map[string]string `json:"reverseTokenMap"`
	Summary         string            `json:"summary"`
}

// ── BH JSON types ─────────────────────────────────────────────────────────────

type bhFile struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		Type string `json:"type"`
	} `json:"meta"`
}

type bhObject struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	IsDeleted        bool   `json:"IsDeleted"`
	Properties       struct {
		Name            string `json:"name"`
		Domain          string `json:"domain"`
		AdminCount      bool   `json:"admincount"`
		HighValue       bool   `json:"highvalue"`
		Enabled         bool   `json:"enabled"`
		Description     string `json:"description"`
		SAMAccountName  string `json:"samaccountname"`
		OperatingSystem string `json:"operatingsystem"`
	} `json:"Properties"`
	Members           []typedPrincipal `json:"Members,omitempty"`
	AllowedToDelegate []typedPrincipal `json:"AllowedToDelegate,omitempty"`
	AllowedToAct      []typedPrincipal `json:"AllowedToAct,omitempty"`
	Aces              []bhAce          `json:"Aces,omitempty"`
}

type typedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type bhAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

// ── Server state ──────────────────────────────────────────────────────────────

var (
	currentGraph *GraphData
	graphMu      sync.RWMutex

	sseClients = make(map[chan string]struct{})
	sseMu      sync.Mutex
)

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	port      := flag.String("port", "8443", "HTTPS listen port")
	provider  := flag.String("provider", "claude", "AI provider: claude | openai | deepseek | gemini | ollama")
	apiKey    := flag.String("api-key", "", "API key (overrides env var and saved config)")
	model     := flag.String("model", "", "Model name (default per provider)")
	ollamaURL := flag.String("ollama-url", "http://localhost:11434", "Ollama base URL")
	flag.Parse()

	// Load saved credentials (nil = first-run setup required)
	if err := loadCreds(); err != nil {
		log.Fatalf("[!] Failed to load credentials: %v", err)
	}

	// Resolve AI config: saved file → flags → env vars
	if err := loadAIConfig(); err != nil {
		log.Printf("[~] No saved AI config (%v), using flags/env vars", err)
		aiCfg = resolveAIConfig(*provider, *apiKey, *model, *ollamaURL)
	} else {
		// CLI --api-key flag overrides saved key (useful for one-shot runs)
		if *apiKey != "" {
			aiCfgMu.Lock()
			aiCfg.APIKey = *apiKey
			aiCfgMu.Unlock()
		}
	}

	mux := http.NewServeMux()

	// Public endpoints (no auth required)
	mux.HandleFunc("/login",           handleLoginPage)
	mux.HandleFunc("/api/auth-status", handleAuthStatus)
	mux.HandleFunc("/api/login",       handleLogin)
	mux.HandleFunc("/api/setup",       handleSetup)
	mux.HandleFunc("/api/logout",      handleLogout)
	mux.HandleFunc("/upload",          handleAgentUpload) // agent exfil — no cookie auth

	// Protected endpoints
	mux.HandleFunc("/",                 protect(handleIndex))
	mux.HandleFunc("/api/events",       protect(handleSSE))
	mux.HandleFunc("/api/offline-load", protect(handleOfflineLoad))
	mux.HandleFunc("/api/chat",         protect(handleChat))
	mux.HandleFunc("/api/analyze",      protect(handleAnalyze))
	mux.HandleFunc("/api/status",       protect(handleStatus))
	mux.HandleFunc("/api/ai-info",      protect(handleAIInfo))
	mux.HandleFunc("/api/ai-config",    protect(handleAIConfig)) // ← in-UI provider switcher

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("[!] TLS cert: %v", err)
	}

	srv := &http.Server{
		Addr:    ":" + *port,
		Handler: addSecurityHeaders(mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0,
	}

	fmt.Println()
	fmt.Println("  ☠  THE GRIMOIRE — AD-Necromancer v2 C2")
	fmt.Println("  ═════════════════════════════════════════")
	fmt.Printf("  ►  UI:        https://0.0.0.0:%s\n", *port)
	fmt.Printf("  ►  Agent:     --exfil https://<ip>:%s/upload\n", *port)
	aiCfgMu.RLock()
	fmt.Printf("  ►  Provider:  %s (%s)\n", aiCfg.Provider, aiCfg.Model)
	aiCfgMu.RUnlock()
	if creds == nil {
		fmt.Println("  ⚠  First run — open the UI to create your account")
	} else {
		fmt.Printf("  ✓  Account:   %s\n", creds.Username)
	}
	fmt.Println()

	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// ── Security headers middleware ───────────────────────────────────────────────

func addSecurityHeaders(next http.Handler) http.Handler {
	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com fonts.googleapis.com",
		"style-src 'self' 'unsafe-inline' fonts.googleapis.com fonts.gstatic.com",
		"font-src fonts.gstatic.com",
		"img-src 'self' data:",
		"connect-src 'self'",
	}, "; ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

// ── AI Config Resolution ──────────────────────────────────────────────────────

func resolveAIConfig(provider, apiKey, model, ollamaURL string) AIConfig {
	cfg := AIConfig{Provider: provider, APIKey: apiKey, Model: model, Endpoint: ollamaURL}

	switch provider {
	case "claude":
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		}
		if cfg.Model == "" {
			cfg.Model = firstNonEmpty(os.Getenv("CLAUDE_MODEL"), "claude-opus-4-5")
		}
	case "openai":
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		}
		if cfg.Model == "" {
			cfg.Model = firstNonEmpty(os.Getenv("OPENAI_MODEL"), "gpt-4o")
		}
	case "deepseek":
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("DEEPSEEK_API_KEY")
		}
		if cfg.Model == "" {
			cfg.Model = "deepseek-chat"
		}
	case "gemini":
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("GEMINI_API_KEY")
		}
		if cfg.Model == "" {
			cfg.Model = firstNonEmpty(os.Getenv("GEMINI_MODEL"), "gemini-1.5-pro")
		}
	case "ollama":
		if cfg.Model == "" {
			cfg.Model = firstNonEmpty(os.Getenv("OLLAMA_MODEL"), "llama3")
		}
		if cfg.Endpoint == "" {
			cfg.Endpoint = firstNonEmpty(os.Getenv("OLLAMA_ENDPOINT"), "http://localhost:11434")
		}
	}
	return cfg
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ── Persisted AI config ───────────────────────────────────────────────────────

func loadAIConfig() error {
	data, err := os.ReadFile(aiCfgPath)
	if err != nil {
		return err
	}
	var cfg AIConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if cfg.Provider == "" {
		return fmt.Errorf("empty provider in saved config")
	}
	aiCfgMu.Lock()
	aiCfg = cfg
	aiCfgMu.Unlock()
	return nil
}

func saveAIConfig(cfg AIConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(aiCfgPath, data, 0600)
}

// ── In-UI AI backend config handler ──────────────────────────────────────────

func handleAIConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		// Return current config — provider, model, endpoint, and whether a key is set.
		// NEVER return the actual API key.
		aiCfgMu.RLock()
		resp := map[string]interface{}{
			"provider":       aiCfg.Provider,
			"model":          aiCfg.Model,
			"endpoint":       aiCfg.Endpoint,
			"key_configured": aiCfg.APIKey != "" || aiCfg.Provider == "ollama",
		}
		aiCfgMu.RUnlock()
		json.NewEncoder(w).Encode(resp)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}

	var req struct {
		Provider string `json:"provider"`
		APIKey   string `json:"api_key"`
		Model    string `json:"model"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad JSON"}`, 400)
		return
	}

	validProviders := map[string]bool{
		"claude": true, "openai": true, "deepseek": true, "gemini": true, "ollama": true,
	}
	if !validProviders[req.Provider] {
		http.Error(w, `{"error":"invalid provider — must be claude|openai|deepseek|gemini|ollama"}`, 400)
		return
	}

	// Build new config, keeping existing key if blank (allows model-only updates)
	aiCfgMu.RLock()
	existingKey := aiCfg.APIKey
	aiCfgMu.RUnlock()

	newKey := req.APIKey
	if newKey == "" {
		newKey = existingKey // preserve if not explicitly changing
	}

	// Resolve defaults for model if blank
	newModel := req.Model
	if newModel == "" {
		switch req.Provider {
		case "claude":
			newModel = "claude-opus-4-5"
		case "openai":
			newModel = "gpt-4o"
		case "deepseek":
			newModel = "deepseek-chat"
		case "gemini":
			newModel = "gemini-1.5-pro"
		case "ollama":
			newModel = "llama3"
		}
	}

	newEndpoint := req.Endpoint
	if newEndpoint == "" && req.Provider == "ollama" {
		newEndpoint = "http://localhost:11434"
	}

	newCfg := AIConfig{
		Provider: req.Provider,
		APIKey:   newKey,
		Model:    newModel,
		Endpoint: newEndpoint,
	}

	// Validate: non-ollama providers require an API key
	if req.Provider != "ollama" && newCfg.APIKey == "" {
		http.Error(w, `{"error":"API key required for this provider"}`, 400)
		return
	}

	if err := saveAIConfig(newCfg); err != nil {
		log.Printf("[!] Failed to save AI config: %v", err)
		http.Error(w, `{"error":"failed to save config"}`, 500)
		return
	}

	aiCfgMu.Lock()
	aiCfg = newCfg
	aiCfgMu.Unlock()

	log.Printf("[+] AI config updated: provider=%s model=%s", newCfg.Provider, newCfg.Model)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"provider":       newCfg.Provider,
		"model":          newCfg.Model,
		"key_configured": newCfg.APIKey != "" || newCfg.Provider == "ollama",
	})
}

// ── Auth middleware ───────────────────────────────────────────────────────────

func protect(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"unauthorized"}`, 401)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		h(w, r)
	}
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("grimoire_session")
	if err != nil {
		return false
	}
	sessionsMu.Lock()
	s, ok := sessions[cookie.Value]
	sessionsMu.Unlock()
	return ok && time.Now().Before(s.ExpiresAt)
}

// ── Auth handlers ─────────────────────────────────────────────────────────────

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(loginHTML)
}

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"setup_required": creds == nil,
		"authenticated":  isAuthenticated(r),
	})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if creds != nil {
		http.Error(w, `{"error":"account already exists"}`, 400)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad JSON"}`, 400)
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	w.Header().Set("Content-Type", "application/json")

	if len(req.Username) < 3 {
		http.Error(w, `{"error":"Username must be at least 3 characters"}`, 400)
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, `{"error":"Password must be at least 8 characters"}`, 400)
		return
	}

	if err := saveCreds(req.Username, req.Password); err != nil {
		http.Error(w, `{"error":"Failed to save credentials: `+err.Error()+`"}`, 500)
		return
	}

	log.Printf("[+] Account created: %s", req.Username)
	createSession(w, req.Username)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad JSON"}`, 400)
		return
	}

	ip := clientIP(r)

	// Rate limiting check
	limiterMu.Lock()
	attempt, exists := loginLimiter[ip]
	if !exists {
		attempt = &loginAttempt{}
		loginLimiter[ip] = attempt
	}
	if time.Now().Before(attempt.LockedUntil) {
		limiterMu.Unlock()
		remaining := time.Until(attempt.LockedUntil).Round(time.Minute)
		http.Error(w, fmt.Sprintf(`{"error":"Too many failed attempts. Try again in %v"}`, remaining), 429)
		return
	}
	limiterMu.Unlock()

	if creds == nil {
		http.Error(w, `{"error":"No account configured. Please set up an account first."}`, 400)
		return
	}

	// Constant-time credential check
	validUser := strings.EqualFold(req.Username, creds.Username)
	validPass := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(req.Password)) == nil

	if !validUser || !validPass {
		limiterMu.Lock()
		attempt.Count++
		if attempt.Count >= maxLoginAttempts {
			attempt.LockedUntil = time.Now().Add(lockoutDuration)
			attempt.Count = 0
			log.Printf("[!] Login lockout applied to IP: %s", ip)
		}
		limiterMu.Unlock()

		http.Error(w, `{"error":"Invalid username or password"}`, 401)
		return
	}

	// Success — clear rate limiter
	limiterMu.Lock()
	delete(loginLimiter, ip)
	limiterMu.Unlock()

	log.Printf("[+] Login: %s from %s", req.Username, ip)
	createSession(w, req.Username)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("grimoire_session"); err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "grimoire_session",
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Secure:  true,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func createSession(w http.ResponseWriter, username string) {
	token := secureToken()
	sessionsMu.Lock()
	sessions[token] = sessionData{
		Username:  username,
		ExpiresAt: time.Now().Add(sessionDuration),
	}
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "grimoire_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── Core page handlers ────────────────────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func handleAIInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	aiCfgMu.RLock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"provider":       aiCfg.Provider,
		"model":          aiCfg.Model,
		"key_configured": aiCfg.APIKey != "" || aiCfg.Provider == "ollama",
	})
	aiCfgMu.RUnlock()
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	graphMu.RLock()
	loaded := currentGraph != nil
	nodes, edges := 0, 0
	if loaded {
		nodes = len(currentGraph.Nodes)
		edges = len(currentGraph.Edges)
	}
	graphMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"loaded": loaded,
		"nodes":  nodes,
		"edges":  edges,
	})
}

// ── Agent + offline upload ────────────────────────────────────────────────────

// agentEvent is broadcast over SSE when an agent connects or finishes uploading.
type agentEvent struct {
	Type      string `json:"type"`      // "connecting" | "received" | "error"
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
	Nodes     int    `json:"nodes,omitempty"`
	Edges     int    `json:"edges,omitempty"`
	Bytes     int    `json:"bytes,omitempty"`
	Error     string `json:"error,omitempty"`
}

func handleAgentUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	agentIP := clientIP(r)

	keyHex := r.Header.Get("X-Session-Key")
	if keyHex == "" {
		http.Error(w, "missing X-Session-Key", 400)
		return
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		http.Error(w, "invalid key hex", 400)
		return
	}

	encData, err := io.ReadAll(io.LimitReader(r.Body, 128<<20))
	if err != nil {
		http.Error(w, "read error", 500)
		return
	}

	// ── Beacon 1: agent has connected and data received, now decrypting ──────
	if evtData, e := json.Marshal(agentEvent{
		Type:      "connecting",
		IP:        agentIP,
		Timestamp: time.Now().Format(time.RFC3339),
		Bytes:     len(encData),
	}); e == nil {
		broadcastSSE("agent", string(evtData))
	}

	graph, err := decryptAndParse(encData, key)
	if err != nil {
		log.Printf("[!] Upload error: %v", err)
		// Beacon: parse error
		if evtData, e := json.Marshal(agentEvent{
			Type:      "error",
			IP:        agentIP,
			Timestamp: time.Now().Format(time.RFC3339),
			Error:     err.Error(),
		}); e == nil {
			broadcastSSE("agent", string(evtData))
		}
		http.Error(w, err.Error(), 400)
		return
	}

	storeAndBroadcast(graph)

	// ── Beacon 2: data fully parsed and graph broadcast ───────────────────────
	if evtData, e := json.Marshal(agentEvent{
		Type:      "received",
		IP:        agentIP,
		Timestamp: time.Now().Format(time.RFC3339),
		Nodes:     len(graph.Nodes),
		Edges:     len(graph.Edges),
		Bytes:     len(encData),
	}); e == nil {
		broadcastSSE("agent", string(evtData))
	}

	log.Printf("[+] Agent upload: %d nodes, %d edges from %s", len(graph.Nodes), len(graph.Edges), agentIP)
	fmt.Fprintln(w, "received")
}

func handleOfflineLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if err := r.ParseMultipartForm(128 << 20); err != nil {
		http.Error(w, "multipart parse: "+err.Error(), 400)
		return
	}

	keyHex := strings.TrimSpace(r.FormValue("key"))
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		http.Error(w, "key must be a 64-char hex string (32 bytes)", 400)
		return
	}

	f, _, err := r.FormFile("zip")
	if err != nil {
		http.Error(w, "missing zip file", 400)
		return
	}
	defer f.Close()

	encData, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "read error", 500)
		return
	}

	graph, err := decryptAndParse(encData, key)
	if err != nil {
		http.Error(w, "decrypt/parse: "+err.Error(), 400)
		return
	}

	storeAndBroadcast(graph)
	log.Printf("[+] Offline load: %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── SSE ───────────────────────────────────────────────────────────────────────

func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 4)
	sseMu.Lock()
	sseClients[ch] = struct{}{}
	sseMu.Unlock()
	defer func() {
		sseMu.Lock()
		delete(sseClients, ch)
		sseMu.Unlock()
		close(ch)
	}()

	// Send current graph immediately if available (typed event so UI handles correctly)
	graphMu.RLock()
	if currentGraph != nil {
		if data, err := json.Marshal(currentGraph); err == nil {
			fmt.Fprintf(w, "event: graph\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
	graphMu.RUnlock()

	hb := time.NewTicker(20 * time.Second)
	defer hb.Stop()

	for {
		select {
		case msg, open := <-ch:
			if !open {
				return
			}
			// msg is already pre-formatted as "event: TYPE\ndata: JSON"
			fmt.Fprintf(w, "%s\n\n", msg)
			flusher.Flush()
		case <-hb.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ── AI Handlers ───────────────────────────────────────────────────────────────

func handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if !aiEnabled() {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "No API key configured. Use the ⚙ AI Backend panel to set your provider and key.",
		})
		return
	}

	var req struct {
		Message string        `json:"message"`
		History []chatMessage `json:"history"`
		Summary string        `json:"summary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", 400)
		return
	}

	msgs := append(req.History, chatMessage{Role: "user", Content: req.Message})
	reply, err := callAI(buildSystemPrompt(req.Summary), msgs)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"reply": reply})
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if !aiEnabled() {
		json.NewEncoder(w).Encode(map[string]string{
			"reply": fmt.Sprintf("⚠ AI analysis disabled — no API key for provider '%s'.\n"+
				"Click ⚙ AI BACKEND in the header to configure your provider and API key.", aiCfg.Provider),
		})
		return
	}

	var req struct {
		Summary string `json:"summary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", 400)
		return
	}

	msgs := []chatMessage{{
		Role: "user",
		Content: "Perform a comprehensive BloodHound privilege archaeology audit. " +
			"Identify the top 5 most significant forgotten or misconfigured privileges, " +
			"stale delegations, residual adminCount artifacts, and non-obvious control paths " +
			"that a human administrator would likely have overlooked. " +
			"For each finding: severity (CRITICAL/HIGH/MEDIUM), the exact BloodHound relationship chain, " +
			"remediation steps, and why this is typically missed during routine AD reviews. " +
			"Sort by severity. Use only entity tokens.",
	}}

	reply, err := callAI(buildSystemPrompt(req.Summary), msgs)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"reply": reply})
}

func aiEnabled() bool {
	aiCfgMu.RLock()
	defer aiCfgMu.RUnlock()
	if aiCfg.Provider == "ollama" {
		return true
	}
	return aiCfg.APIKey != ""
}

func buildSystemPrompt(summary string) string {
	return fmt.Sprintf(`You are the Necromancer AI — an expert Active Directory auditor and privilege archaeology analyst.

Your purpose is to analyze BloodHound dataset exports and surface forgotten, stale, or misconfigured privileges that human administrators overlooked during the normal lifecycle of an Active Directory environment. This is an authorized security audit and hygiene review tool.

You are NOT performing any offensive operation. You are performing PRIVILEGE ARCHAEOLOGY:
- Identifying delegations that were set and forgotten
- Surfacing adminCount residue from historical group membership
- Finding stale control edges that should have been revoked
- Highlighting non-obvious misconfigurations that create unintended access paths
- Explaining WHY each finding exists (root cause) and HOW to remediate it

TOKENIZED ENVIRONMENT DATA (use ONLY these tokens in responses):
%s

RULES:
1. Refer to all AD objects by their ENTITY_NNN tokens only — never use real names directly
2. Surface NON-OBVIOUS findings only — skip trivial built-in admin relationships
3. For "What If" impact analysis: trace the BloodHound relationship chain step by step and explain the blast radius of a compromise, framed as a remediation priority
4. Format responses with CRITICAL/HIGH/MEDIUM severity headers and relationship chains using → arrows
5. Always include: the specific BloodHound relationship type, why it exists (root cause), and remediation guidance
6. Every finding must be grounded in this environment's actual dataset relationships
7. Frame all analysis as: "this misconfiguration/forgotten privilege COULD be abused by a threat actor" — you are the auditor discovering the risk, not the threat actor exploiting it`, summary)
}

// ── AI provider dispatch ──────────────────────────────────────────────────────
// NOTE: The provider implementations below are intentionally self-contained here.
// The internal/claude, openai, deepseek, gemini, ollama packages implement the
// single-turn ai.AIClient Summon(sys,user) interface used by cmd/ad-necromancer.
// The Grimoire requires multi-turn conversation with []chatMessage history,
// so we maintain separate but equivalent implementations here.

func callAI(system string, messages []chatMessage) (string, error) {
	aiCfgMu.RLock()
	cfg := aiCfg
	aiCfgMu.RUnlock()

	switch cfg.Provider {
	case "claude":
		return callClaude(cfg, system, messages)
	case "openai":
		return callOpenAICompat(cfg, "https://api.openai.com/v1/chat/completions", system, messages)
	case "deepseek":
		return callOpenAICompat(cfg, "https://api.deepseek.com/v1/chat/completions", system, messages)
	case "ollama":
		ep := strings.TrimRight(cfg.Endpoint, "/")
		return callOpenAICompat(cfg, ep+"/v1/chat/completions", system, messages)
	case "gemini":
		return callGemini(cfg, system, messages)
	default:
		return "", fmt.Errorf("unsupported AI provider: %s", cfg.Provider)
	}
}

// Claude (Anthropic Messages API) ─────────────────────────────────────────────

type claudeReq struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	System    string        `json:"system"`
	Messages  []chatMessage `json:"messages"`
}

type claudeResp struct {
	Content []struct{ Text string `json:"text"` } `json:"content"`
	Error   struct{ Message string `json:"message"` } `json:"error"`
}

func callClaude(cfg AIConfig, system string, messages []chatMessage) (string, error) {
	body, _ := json.Marshal(claudeReq{
		Model:     cfg.Model,
		MaxTokens: 4096,
		System:    system,
		Messages:  messages,
	})

	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("x-api-key", cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := (&http.Client{Timeout: 180 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("claude: %w", err)
	}
	defer resp.Body.Close()

	var cr claudeResp
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Error.Message != "" {
		return "", fmt.Errorf("claude API: %s", cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", fmt.Errorf("claude: empty response")
	}
	return cr.Content[0].Text, nil
}

// OpenAI-compatible (OpenAI, DeepSeek, Ollama) ────────────────────────────────

type oaiReq struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens,omitempty"`
}

type oaiResp struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error struct{ Message string `json:"message"` } `json:"error"`
}

func callOpenAICompat(cfg AIConfig, endpoint, system string, messages []chatMessage) (string, error) {
	all := append([]chatMessage{{Role: "system", Content: system}}, messages...)

	body, _ := json.Marshal(oaiReq{Model: cfg.Model, Messages: all, MaxTokens: 4096})
	req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := (&http.Client{Timeout: 180 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %w", cfg.Provider, err)
	}
	defer resp.Body.Close()

	var or oaiResp
	json.NewDecoder(resp.Body).Decode(&or)
	if or.Error.Message != "" {
		return "", fmt.Errorf("%s API: %s", cfg.Provider, or.Error.Message)
	}
	if len(or.Choices) == 0 {
		return "", fmt.Errorf("%s: empty response", cfg.Provider)
	}
	return or.Choices[0].Message.Content, nil
}

// Gemini (Google generativelanguage API) ──────────────────────────────────────

type geminiReq struct {
	SystemInstruction *geminiContent  `json:"system_instruction,omitempty"`
	Contents          []geminiContent `json:"contents"`
	GenerationConfig  struct {
		MaxOutputTokens int `json:"maxOutputTokens"`
	} `json:"generationConfig"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResp struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
	Error struct{ Message string `json:"message"` } `json:"error"`
}

func callGemini(cfg AIConfig, system string, messages []chatMessage) (string, error) {
	if cfg.APIKey == "" {
		return "", fmt.Errorf("no GEMINI_API_KEY configured")
	}

	contents := make([]geminiContent, 0, len(messages))
	for _, m := range messages {
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		contents = append(contents, geminiContent{
			Role:  role,
			Parts: []geminiPart{{Text: m.Content}},
		})
	}

	greq := geminiReq{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{Text: system}}},
		Contents:          contents,
	}
	greq.GenerationConfig.MaxOutputTokens = 4096

	body, _ := json.Marshal(greq)
	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		cfg.Model, cfg.APIKey)

	resp, err := (&http.Client{Timeout: 180 * time.Second}).Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("gemini: %w", err)
	}
	defer resp.Body.Close()

	var gr geminiResp
	json.NewDecoder(resp.Body).Decode(&gr)
	if gr.Error.Message != "" {
		return "", fmt.Errorf("gemini API: %s", gr.Error.Message)
	}
	if len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: empty response")
	}
	return gr.Candidates[0].Content.Parts[0].Text, nil
}

// ── BH Zip parsing ────────────────────────────────────────────────────────────

func decryptAndParse(encData, key []byte) (*GraphData, error) {
	plain, err := crypto.Decrypt(encData, key)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM decrypt: %w", err)
	}
	return parseZip(plain)
}

// parseZip parses a decrypted BloodHound CE v6 zip into a GraphData.
// Uses two passes so edges are only emitted when both endpoints are known nodes:
//  1. Collect all valid objects and build a nodeID set.
//  2. Emit edges — skip any whose source or target is not in nodeIDs.
//
// This prevents Cytoscape from crashing with "nonexistent source/target" on
// Members/ACEs that contain DNs, cross-domain SIDs, or deleted-object refs
// with no corresponding node in this dataset.
func parseZip(data []byte) (*GraphData, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}

	graph := &GraphData{
		Nodes: make([]GraphNode, 0, 256),
		Edges: make([]GraphEdge, 0, 512),
	}

	fileTypes := map[string]string{
		"users.json": "User", "groups.json": "Group", "computers.json": "Computer",
		"domains.json": "Domain", "gpos.json": "GPO", "ous.json": "OU",
		"certtemplates.json": "CertTemplate", "enterprisecas.json": "EnterpriseCA",
	}

	seen := make(map[string]bool)

	// --- Pass 1: read every file, collect valid objects ---
	type rawEntry struct {
		obj     bhObject
		objType string
	}
	var entries []rawEntry

	for _, f := range zr.File {
		base := strings.ToLower(f.Name)
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		objType, ok := fileTypes[base]
		if !ok {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		fb, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		var bhf bhFile
		if err := json.Unmarshal(fb, &bhf); err != nil {
			continue
		}
		for _, raw := range bhf.Data {
			var obj bhObject
			if err := json.Unmarshal(raw, &obj); err != nil || obj.IsDeleted || obj.ObjectIdentifier == "" || seen[obj.ObjectIdentifier] {
				continue
			}
			seen[obj.ObjectIdentifier] = true
			entries = append(entries, rawEntry{obj, objType})
		}
	}

	// --- Pass 2: build nodes + index of known node IDs ---
	nodeIDs := make(map[string]bool, len(entries))
	for _, e := range entries {
		obj := e.obj
		label := obj.Properties.Name
		if label == "" {
			label = obj.ObjectIdentifier
		}
		graph.Nodes = append(graph.Nodes, GraphNode{
			ID:    obj.ObjectIdentifier,
			Label: label,
			Type:  e.objType,
			Properties: map[string]string{
				"domain":      obj.Properties.Domain,
				"admincount":  boolStr(obj.Properties.AdminCount),
				"highvalue":   boolStr(obj.Properties.HighValue),
				"enabled":     boolStr(obj.Properties.Enabled),
				"description": obj.Properties.Description,
				"sam":         obj.Properties.SAMAccountName,
				"os":          obj.Properties.OperatingSystem,
			},
		})
		nodeIDs[obj.ObjectIdentifier] = true
	}

	// --- Pass 3: emit edges — only when both endpoints exist in nodeIDs ---
	addEdge := func(src, tgt, rel string) {
		if src != "" && tgt != "" && src != tgt && nodeIDs[src] && nodeIDs[tgt] {
			graph.Edges = append(graph.Edges, GraphEdge{Source: src, Target: tgt, Relation: rel})
		}
	}

	for _, e := range entries {
		obj := e.obj
		sid := obj.ObjectIdentifier
		for _, m := range obj.Members {
			addEdge(m.ObjectIdentifier, sid, "MemberOf")
		}
		for _, d := range obj.AllowedToDelegate {
			addEdge(sid, d.ObjectIdentifier, "AllowedToDelegate")
		}
		for _, a := range obj.AllowedToAct {
			addEdge(a.ObjectIdentifier, sid, "AllowedToActOnBehalfOf")
		}
		for _, ace := range obj.Aces {
			if !ace.IsInherited && ace.PrincipalSID != "" && isHighValueRight(ace.RightName) {
				addEdge(ace.PrincipalSID, sid, ace.RightName)
			}
		}
	}

	buildTokenMap(graph)
	graph.Summary = buildSummary(graph)
	return graph, nil
}

func isHighValueRight(right string) bool {
	for _, r := range []string{"GenericAll", "DCSync", "WriteDACL", "WriteOwner", "GenericWrite", "AllExtendedRights", "ForceChangePassword", "Owns", "AddMember", "AddAllowedToAct"} {
		if strings.EqualFold(right, r) {
			return true
		}
	}
	return false
}

func buildTokenMap(g *GraphData) {
	tm := make(map[string]string, len(g.Nodes))
	rm := make(map[string]string, len(g.Nodes))
	for i, n := range g.Nodes {
		if n.Label == "" {
			continue
		}
		tok := fmt.Sprintf("ENTITY_%03d", i+1)
		tm[n.Label] = tok
		rm[tok] = n.Label
		g.Nodes[i].Properties["token"] = tok
	}
	g.TokenMap, g.ReverseTokenMap = tm, rm
}

func buildSummary(g *GraphData) string {
	counts := make(map[string]int)
	for _, n := range g.Nodes {
		counts[n.Type]++
	}
	labelByID := make(map[string]string, len(g.Nodes))
	for _, n := range g.Nodes {
		labelByID[n.ID] = n.Label
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== AD ENVIRONMENT SUMMARY ===\n")
	fmt.Fprintf(&sb, "Users:%d Groups:%d Computers:%d Domains:%d GPOs:%d OUs:%d CertTemplates:%d EnterpriseCAs:%d | Relationships:%d\n\n",
		counts["User"], counts["Group"], counts["Computer"], counts["Domain"],
		counts["GPO"], counts["OU"], counts["CertTemplate"], counts["EnterpriseCA"], len(g.Edges))

	sb.WriteString("=== HIGH-VALUE ENTITIES ===\n")
	found := 0
	for _, n := range g.Nodes {
		if n.Properties["admincount"] == "true" || n.Properties["highvalue"] == "true" {
			tok := n.Label
			stale := ""
			if n.Properties["enabled"] == "false" {
				stale = " [STALE-DISABLED]"
			}
			fmt.Fprintf(&sb, "- %s (%s%s, domain=%s)\n", tok, n.Type, stale, n.Properties["domain"])
			found++
		}
	}
	if found == 0 {
		sb.WriteString("(none)\n")
	}

	sb.WriteString("\n=== CONTROL EDGES (first 60) ===\n")
	for i, e := range g.Edges {
		if i >= 60 {
			fmt.Fprintf(&sb, "...and %d more\n", len(g.Edges)-60)
			break
		}
		s := labelByID[e.Source]
		t := labelByID[e.Target]
		if s == "" { s = e.Source }
		if t == "" { t = e.Target }
		fmt.Fprintf(&sb, "- %s →[%s]→ %s\n", s, e.Relation, t)
	}
	return sb.String()
}

// ── SSE broadcast ─────────────────────────────────────────────────────────────

// broadcastSSE sends a typed SSE message (event: TYPE\ndata: DATA) to all
// connected clients. The channel carries pre-formatted strings; handleSSE
// appends the trailing double-newline when writing to the response.
func broadcastSSE(eventType, data string) {
	msg := fmt.Sprintf("event: %s\ndata: %s", eventType, data)
	sseMu.Lock()
	for ch := range sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
	sseMu.Unlock()
}

func storeAndBroadcast(g *GraphData) {
	graphMu.Lock()
	currentGraph = g
	graphMu.Unlock()

	data, _ := json.Marshal(g)
	broadcastSSE("graph", string(data))
}

// ── Credentials ───────────────────────────────────────────────────────────────

func loadCreds() error {
	data, err := os.ReadFile(credsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // first run
		}
		return err
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	creds = &c
	return nil
}

func saveCreds(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c := Credentials{Username: username, PasswordHash: string(hash)}
	data, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(credsPath, data, 0600); err != nil {
		return err
	}
	creds = &c
	return nil
}

// ── TLS ───────────────────────────────────────────────────────────────────────

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
						if ip4 := ipNet.IP.To4(); ip4 != nil {
							ips = append(ips, ip4)
						}
					}
				}
			}
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "AD-Necromancer Grimoire"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func secureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
