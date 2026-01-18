# AD-Necromancer

> **"Humans forget. Directories do not."**

An intelligence engine for discovering abandoned and forgotten Active Directory identities that human operators have lost track of.

---

## 🔧 Setup

### Prerequisites

- Go 1.21 or higher
- AI Backend (choose one):
  - **DeepSeek** (default) - [Get API key](https://platform.deepseek.com/)
  - **OpenAI** - [Get API key](https://platform.openai.com/)
  - **Google Gemini** - [Get API key](https://aistudio.google.com/app/apikey)
  - **Anthropic Claude** - [Get API key](https://console.anthropic.com/)
  - **Ollama** (on-premise) - [Install Ollama](https://ollama.ai/)
- BloodHound JSON data

### 1. Configure AI Backend

#### Option A: DeepSeek (Default)

```bash
# Linux/macOS
export DEEPSEEK_API_KEY="your-api-key-here"

# Windows PowerShell
$env:DEEPSEEK_API_KEY="your-api-key-here"
```

#### Option B: OpenAI

```bash
# Linux/macOS
export OPENAI_API_KEY="your-api-key-here"
export OPENAI_MODEL="gpt-4o-mini"  # Optional, defaults to gpt-4o-mini

# Windows PowerShell
$env:OPENAI_API_KEY="your-api-key-here"
$env:OPENAI_MODEL="gpt-4o-mini"  # Optional
```

#### Option C: Google Gemini

```bash
# Linux/macOS
export GEMINI_API_KEY="your-api-key-here"
export GEMINI_MODEL="gemini-1.5-flash"  # Optional, defaults to gemini-1.5-flash

# Windows PowerShell
$env:GEMINI_API_KEY="your-api-key-here"
$env:GEMINI_MODEL="gemini-1.5-flash"  # Optional
```

#### Option D: Anthropic Claude

```bash
# Linux/macOS
export CLAUDE_API_KEY="your-api-key-here"
export CLAUDE_MODEL="claude-3-5-sonnet-20241022"  # Optional, defaults to claude-3-5-sonnet

# Windows PowerShell
$env:CLAUDE_API_KEY="your-api-key-here"
$env:CLAUDE_MODEL="claude-3-5-sonnet-20241022"  # Optional
```

#### Option E: Ollama (On-Premise)

```bash
# Install Ollama first: https://ollama.ai/
# Pull a model
ollama pull llama3

# Optional: Configure endpoint and model
export OLLAMA_ENDPOINT="http://localhost:11434"  # Default
export OLLAMA_MODEL="llama3"  # Default
```

---

## 🏗️ Build

```bash
go build -o ad-necromancer ./cmd/ad-necromancer
```

**Windows:**
```bash
go build -o ad-necromancer.exe ./cmd/ad-necromancer
```

---

## 🚀 Run

### Default (DeepSeek)
```bash
./ad-necromancer --data /path/to/bloodhound/json
```

### With OpenAI
```bash
./ad-necromancer --data /path/to/bloodhound/json --openai
```

### With Google Gemini
```bash
./ad-necromancer --data /path/to/bloodhound/json --gemini
```

### With Anthropic Claude
```bash
./ad-necromancer --data /path/to/bloodhound/json --claude
```

### With Ollama (On-Premise)
```bash
./ad-necromancer --data /path/to/bloodhound/json --on-premise
```

### Parameters

- `--data` - Path to directory containing BloodHound JSON files (required)
- `--on-premise` - Use local Ollama backend (optional)
- `--openai` - Use OpenAI backend (optional)
- `--gemini` - Use Google Gemini backend (optional)
- `--claude` - Use Anthropic Claude backend (optional)
- `--sample-size` - Max entities per type to send to LLM (default: 20)
  - Controls how many users, groups, computers, cert templates, and enterprise CAs are sampled
  - Lower values = faster analysis, smaller API payload
  - Higher values = more comprehensive analysis, larger API payload
  - Recommended: 10-30 depending on dataset size and API limits
  - Example: `--sample-size 30` sends 30 users, 30 groups, 30 computers, etc.
- `--no-privacy-cloak` - Disable privacy tokenization (send real data to AI)
- `--save-mapping` - Save tokenization mapping to disk for debugging

**Backend Priority** (if multiple flags specified):
1. Ollama (on-premise)
2. Claude
3. Gemini
4. OpenAI
5. DeepSeek (default)

### Example

```bash
# Default: DeepSeek with Privacy Cloak enabled
./ad-necromancer --data /path/to/bloodhound/json

# OpenAI with custom sample size
./ad-necromancer --data /path/to/bloodhound/json --openai --sample-size 30

# On-premise Ollama (Privacy Cloak disabled by default)
./ad-necromancer --data /path/to/bloodhound/json --on-premise
```

---

## 🔒 Privacy Cloak

**Privacy Cloak** is a tokenization-based privacy protection system that ensures your sensitive Active Directory data **never reaches remote AI services** while maintaining full analytical capabilities.

### How It Works

```
┌─────────────────┐
│  BloodHound     │
│  JSON Data      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Privacy Cloak  │  ← Tokenizes sensitive data
│  (Tokenizer)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Tokenized      │  Example: "ADMIN@CORP.COM" → "ID_U_42B1"
│  Data           │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Remote AI      │  ← AI analyzes tokens, not real data
│  (DeepSeek/     │
│   OpenAI)       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AI Response    │  Example: "ID_U_42B1 has GenericAll on ID_G_9A22"
│  (tokenized)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  De-tokenizer   │  ← Converts tokens back to real names
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Real Names     │  Example: "ADMIN@CORP.COM has GenericAll on DOMAIN ADMINS"
│  Output         │
└─────────────────┘
```

### What Gets Protected

Privacy Cloak tokenizes **all** sensitive identifiers:

- ✅ **Domain/forest names** - `PHANTOM.CORP` → `DOM_7F3A`
- ✅ **Usernames** - `T1_TONYMONTANA@PHANTOM.CORP` → `ID_U_42B1`
- ✅ **Group names** - `DOMAIN ADMINS@PHANTOM.CORP` → `ID_G_9A22`
- ✅ **Computer hostnames** - `DC01.PHANTOM.CORP` → `H_T0_19C2`
- ✅ **Distinguished Names** - `OU=COMPUTERS,DC=PHANTOM,DC=CORP` → `OU_0A91`
- ✅ **GPO names** - `Default Domain Policy` → `GPO_33D7`
- ✅ **SIDs** - `S-1-5-21-...-500` → `SID_9C10`
- ✅ **Certificate Templates** - `ESC1-VulnTemplate` → `TMPL_4E82`
- ✅ **Enterprise CAs** - `PHANTOM-CA` → `CA_7B19`

### What's Preserved

Privacy Cloak maintains **full analytical capabilities**:

- ✅ **Relationship types** - GenericAll, WriteDACL, AddMember, etc.
- ✅ **Risk levels** - Critical, High, Medium, Low
- ✅ **Tier classifications** - Tier 0, Tier 1, etc.
- ✅ **Security flags** - highvalue, admincount, enabled
- ✅ **Attack path structure** - Complete exploit chains

### Token Format

Tokens are **deterministic** (same input = same token) and **type-aware** for readability:

| Entity Type | Token Prefix | Example | Real Value |
|-------------|--------------|---------|------------|
| Domain | `DOM_` | `DOM_7F3A` | `PHANTOM.CORP` |
| User | `ID_U_` | `ID_U_42B1` | `TONYMONTANA@PHANTOM.CORP` |
| Group | `ID_G_` | `ID_G_9A22` | `DOMAIN ADMINS@PHANTOM.CORP` |
| Computer (Tier 0) | `H_T0_` | `H_T0_19C2` | `DC01.PHANTOM.CORP` |
| Computer (Tier 1) | `H_T1_` | `H_T1_8B4F` | `WEB01.PHANTOM.CORP` |
| Computer (Other) | `H_` | `H_3C91` | `WORKSTATION42.PHANTOM.CORP` |
| OU | `OU_` | `OU_0A91` | `OU=COMPUTERS,DC=PHANTOM,DC=CORP` |
| GPO | `GPO_` | `GPO_33D7` | `Default Domain Policy` |
| SID | `SID_` | `SID_9C10` | `S-1-5-21-...-500` |
| Cert Template | `TMPL_` | `TMPL_4E82` | `ESC1-VulnTemplate` |
| Enterprise CA | `CA_` | `CA_7B19` | `PHANTOM-CA` |

### Usage Examples

#### Default Behavior (Automatic)

```bash
# Remote AI → Privacy Cloak ENABLED automatically
./ad-necromancer --data /path/to/data --openai
```

**Output:**
```
[🔒] Privacy Cloak: ENABLED (tokenized remote AI)
[🔒] Privacy Cloak: 60 entities tokenized (45 tokens generated)
```

#### Disable Privacy Cloak (Not Recommended for Remote AI)

```bash
# Send real data to remote AI (use with caution!)
./ad-necromancer --data /path/to/data --openai --no-privacy-cloak
```

**Output:**
```
[!] Privacy Cloak: DISABLED (sending real data to remote AI)
```

#### On-Premise (Privacy Cloak Disabled by Default)

```bash
# Local Ollama → Data stays on your machine
./ad-necromancer --data /path/to/data --on-premise
```

**Output:**
```
[*] Privacy Cloak: DISABLED (on-premise AI)
```

#### Save Tokenization Mapping

```bash
# Save mapping for debugging or audit purposes
./ad-necromancer --data /path/to/data --openai --save-mapping
```

**Output:**
```
[✓] Mapping saved to .necromancer/mappings/run_20260118_230530.json
[!] WARNING: Mapping file contains sensitive data. Protect it like credentials.
```

### Example: Before & After

#### Before (Real Data)
```json
{
  "users": [
    {
      "name": "T1_TONYMONTANA@PHANTOM.CORP",
      "domain": "PHANTOM.CORP",
      "admincount": true,
      "pwdlastset": 1704067200
    }
  ]
}
```

#### After (Tokenized Data Sent to AI)
```json
{
  "entities": [
    {
      "token": "ID_U_42B1",
      "type": "User",
      "admincount": true,
      "age": "~892 days"
    }
  ]
}
```

#### AI Response (Tokenized)
```
🔴 CRITICAL: Forgotten Admin with Dangerous Control

User ID_U_42B1 has GenericAll on Group ID_G_9A22 in domain DOM_7F3A.
This account has not changed password in ~892 days and retains
administrative privileges on Tier 0 computer H_T0_19C2.
```

#### Final Output (De-tokenized for Display)
```
🔴 CRITICAL: Forgotten Admin with Dangerous Control

User T1_TONYMONTANA@PHANTOM.CORP has GenericAll on Group DOMAIN ADMINS@PHANTOM.CORP
in domain PHANTOM.CORP. This account has not changed password in ~892 days and retains
administrative privileges on Tier 0 computer DC01.PHANTOM.CORP.
```

### Security Features

#### 1. Deterministic Hashing
- Uses SHA256 with per-run salt
- Same input always produces same token (within a run)
- First 4 hex characters for token suffix

#### 2. Paranoia Mode
- Automatically strips unknown domains from AI responses
- Regex pattern matching for potential data leaks
- Replaces suspicious content with `[REDACTED]`

#### 3. No Raw JSON to AI
- Sends only sanitized, tokenized entity summaries
- Preserves structure and relationships
- Removes all identifying information

#### 4. Mapping Protection
- Auto-creates `.gitignore` in `.necromancer/` directory
- File permissions set to `0600` (owner read/write only)
- Security warnings when saving mappings

### When to Use Privacy Cloak

| Scenario | Privacy Cloak | Reason |
|----------|---------------|--------|
| **Production AD data + Remote AI** | ✅ **ON** (default) | Protects sensitive data |
| **Compliance requirements** | ✅ **ON** | GDPR, HIPAA, SOC2 compliance |
| **Public cloud AI** | ✅ **ON** | Data leaves your network |
| **On-premise Ollama** | ⚪ **OFF** (default) | Data stays local |
| **Test/lab environment** | ⚪ **Optional** | Your choice |
| **Debugging tokenization** | ✅ **ON** + `--save-mapping` | Audit trail |

### Compliance Benefits

Privacy Cloak helps meet regulatory requirements:

- **GDPR** - No personal identifiers sent to third parties
- **HIPAA** - Protected health information stays local
- **SOC2** - Demonstrates data protection controls
- **PCI DSS** - Sensitive data tokenization
- **NIST** - Follows data minimization principles

### Performance Impact

- **Tokenization**: ~5ms for 1000 entities
- **De-tokenization**: ~2ms for typical response
- **Memory**: ~1MB for 10,000 token mappings
- **Network**: Reduced payload size (tokens shorter than real names)

**Result**: Privacy Cloak adds **negligible overhead** while providing **maximum protection**.

---

## 📊 Sample Output

AD-Necromancer produces detailed, intelligence-style reports for each discovered attack path:

### 🎯 Finding Structure

Each finding includes:
- **Entity Details** - Name, type, status, and origin
- **Necromancy Analysis** - AI-powered analysis of the control path
- **Undead Control Path** - Visual ASCII graph showing the attack chain
- **Human Blind Spot** - Why humans missed this
- **Impact Assessment** - Severity and stealth rating
- **Why This Exists** - Root cause analysis
- **Execution Vectors** - Specific attack techniques
- **Detection Rules** - How to monitor for this
- **Mitigation** - How to fix it
- **Resurrected Chain** - Detailed exploitation narrative

---

### 📋 Example Output

```
    ___    ____  _   __                                                    
   /   |  / __ \/ | / /__  ______________  ____ ___  ____ _____  ________  _____
  / /| | / / / /  |/ / _ \/ ___/ ___/ __ \/ __  __ \/ __  / __ \/ ___/ _ \/ ___/
 / ___ |/ /_/ / /|  /  __/ /__/ /  / /_/ / / / / / / /_/ / / / / /__/  __/ /    
/_/  |_/_____/_/ |_/\___/\___/_/   \____/_/ /_/ /_/\__,_/_/ /_/\___/\___/_/     
                                                                                
             "Humans forget. Directories do not."


[*] Exhuming artifacts from the directory...
[+] Loaded: 100 Users, 285 Groups, 34 Computers, 3 Domains, 32 GPOs, 20 OUs, 106 CertTemplates, 4 EnterpriseCAs

[*] Disturbing dormant identities...
[*] Listening for forgotten control...
[*] Resurrecting dead privileges...
[*] Using intelligent sampling (prioritizing high-value targets)...
[*] Analysis Scope (Sampled): 20 Users, 20 Groups, 20 Computers, 20 CertTemplates, 4 EnterpriseCAs


╔══════════════════════════════════════════════════════════════════════════════╗
║ ☠ UNDEAD CONTROL PATH RESURRECTED — CRITICAL                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

[ENTITY]
  Name   : JONAS-TEST-MS01.PHANTOM.CORP
  Type   : Computer
  Status : Abandoned delegation residue
  Origin : Legacy test server with forgotten RBCD configuration

[NECROMANCY ANALYSIS]
  ▸ This computer has an AddAllowedToAct control edge granted to user S-1-5-21-...-2132
  ▸ Enables Resource-Based Constrained Delegation attacks
  ▸ Forgotten control edge allows impersonation of any user to any service

[UNDEAD CONTROL PATH]

         🟣 User S-1-5-21-...-2132
                │ AddAllowedToAct
                ▼
         🔴 JONAS-TEST-MS01.PHANTOM.CORP
                │ RBCD Configuration
                ▼
         🔴 Any Service Principal
                │ Service Ticket Acquisition
                ▼
         🔴 Target System Compromise

[HUMAN BLIND SPOT]
  ▸ Not monitored since test environment decommissioned
  ▸ No RBCD configuration audits performed
  ▸ Forgotten after 'JONAS-TEST' project completed
  ▸ Computer password last set ~2 years ago

[IMPACT]
  ☠ Complete compromise of JONAS-TEST-MS01 and lateral movement capabilities
  ☠ Stealth: Medium (RBCD configuration changes are logged)
  ☠ Human Detection Probability: Medium (if RBCD monitoring exists)

[WHY THIS EXISTS]
  Test or development configurations that were never cleaned up. RBCD permissions 
  were likely granted for application testing and remained after testing concluded.

[EXECUTION VECTORS]
  • [DELEGATION ABUSE] AddAllowedToAct → RBCD Attack | Target: JONAS-TEST-MS01
  • [RBCD EXPLOIT] Configure delegation → Service Ticket Forgery | Scope: Any SPN
  • [LATERAL MOVEMENT] Service ticket → Target system access | Impact: Domain compromise

[DETECTION RULES]
  • Monitor: AddAllowedToAct permission modifications on computer objects
  • Alert: RBCD configuration changes by non-admin users
  • Hunt: Computer objects with non-default RBCD permissions

[MITIGATION]
  Audit all RBCD configurations, remove unnecessary AddAllowedToAct permissions, 
  implement RBCD change monitoring, and establish regular review processes.

[RESURRECTED CHAIN]
  An unidentified user holds the AddAllowedToAct permission on JONAS-TEST-MS01. 
  This enables RBCD attacks where the user can configure the computer to impersonate 
  any service principal in the domain, leading to lateral movement and privilege escalation.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╔══════════════════════════════════════════════════════════════════════════════╗
║ ☠ UNDEAD CONTROL PATH RESURRECTED — HIGH                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

[ENTITY]
  Name   : ENTERPRISE ADMINS@PHANTOM.CORP
  Type   : Group
  Status : Forgotten cross-forest control delegation
  Origin : Legacy forest trust configuration

[NECROMANCY ANALYSIS]
  ▸ Enterprise Admins from PHANTOM.CORP has WriteDacl, WriteOwner, GenericWrite on GHOST.CORP GPOs
  ▸ Cross-forest control path where administrative permissions were never revoked
  ▸ Allows modification of critical domain policies in foreign forest

[UNDEAD CONTROL PATH]

         🟣 PHANTOM.CORP Enterprise Admins
                │ WriteDacl/WriteOwner/GenericWrite
                ▼
         🔴 GHOST.CORP GPOs
                │ Default Domain Policy
                │ DC Policy
                ▼
         🔴 GHOST.CORP Domain Control

[HUMAN BLIND SPOT]
  ▸ Not monitored since forest trust decommissioned
  ▸ No cross-forest permission audits performed
  ▸ Forgotten after GHOST.CORP migration project completed
  ▸ Password last set for GHOST.CORP KRBTGT ~3 years ago

[IMPACT]
  ☠ Complete compromise of GHOST.CORP forest through GPO modification
  ☠ Stealth: High (cross-forest activity often unmonitored)
  ☠ Human Detection Probability: Low (forgotten trust artifact)

[WHY THIS EXISTS]
  Incomplete cleanup of cross-forest permissions after decommissioning forest trusts.
  Administrative groups were granted permissions for migration but never revoked.

[EXECUTION VECTORS]
  • [CROSS-FOREST ABUSE] WriteDacl on GPO → Policy Modification | Target: GHOST.CORP
  • [GPO ABUSE] GenericWrite → Malicious Setting Injection | Impact: Domain-wide
  • [ACL ABUSE] WriteOwner → GPO Takeover | Scope: GHOST.CORP forest

[DETECTION RULES]
  • Monitor: Cross-forest WriteDacl/WriteOwner operations on GPOs
  • Alert: Modification of GHOST.CORP GPOs by PHANTOM.CORP principals
  • Hunt: Enterprise Admins group with permissions in foreign forests

[MITIGATION]
  Immediately audit and remove all cross-forest permissions, implement regular 
  cross-forest ACL reviews, and establish monitoring for cross-domain administrative activity.

[RESURRECTED CHAIN]
  Enterprise Admins from PHANTOM.CORP maintains direct control edges over critical 
  GPOs in GHOST.CORP forest. Through WriteDacl permissions, this group can modify 
  security descriptors enabling policy injection and eventual domain compromise.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╔══════════════════════════════════════════════════════════════════════════════╗
║                           RESURRECTION COMPLETE                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

[✓] Total Undead Paths Discovered: 5
                                                                                
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  🔴 CRITICAL RISK: 1 path(s) - IMMEDIATE ACTION REQUIRED!              ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    🟠 High Risk: 2 path(s) - Prioritize remediation
    🟡 Medium Risk: 2 path(s) - Schedule for review
                                                                                
    ⚠️  WARNING: Critical/High risk findings detected!
    ⚠️  These forgotten identities could lead to FULL DOMAIN COMPROMISE!

    💀 The dead have spoken. Will you listen?
```

---

### 🎨 Output Features

- **Color-coded severity** - Critical (🔴), High (🟠), Medium (🟡), Low (🟢)
- **ASCII art graphs** - Visual representation of attack paths
- **Emoji indicators** - 🟣 (abandoned), 🔴 (critical), 🟠 (high-value)
- **Structured sections** - Consistent format for easy parsing
- **Risk prioritization** - Sorted by severity for triage
- **Actionable intelligence** - Specific detection rules and mitigation steps

---

## 🔒 Security Note

Never commit your API key to version control. Always use environment variables.

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 Report Bugs
Found an issue? [Create an issue](https://github.com/0xSense1/AD-Necromancer/issues/new) with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Go version, backend used)

### 💡 Suggest Features
Have ideas? [Open a feature request](https://github.com/0xSense1/AD-Necromancer/issues/new) with:
- Use case description
- Proposed solution
- Any relevant examples or mockups

### 🔧 Submit Pull Requests
Code contributions are always welcome!

**Guidelines:**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly (all three backends if possible)
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

**Areas we'd love help with:**
- Additional AI backend integrations (Anthropic, Gemini, etc.)
- Performance optimizations
- Additional BloodHound entity type support
- Improved prompt engineering
- Documentation improvements
- Bug fixes and error handling

---

## 📝 License

MIT