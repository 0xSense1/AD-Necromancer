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

#### Option C: Ollama (On-Premise)

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

### With Ollama (On-Premise)
```bash
./ad-necromancer --data /path/to/bloodhound/json --on-premise
```

### With OpenAI
```bash
./ad-necromancer --data /path/to/bloodhound/json --openai
```

### Parameters

- `--data` - Path to directory containing BloodHound JSON files (required)
- `--on-premise` - Use local Ollama backend (optional)
- `--openai` - Use OpenAI backend (optional)
- `--sample-size` - Max entities per type to send to LLM (default: 20)
  - Controls how many users, groups, computers, cert templates, and enterprise CAs are sampled
  - Lower values = faster analysis, smaller API payload
  - Higher values = more comprehensive analysis, larger API payload
  - Recommended: 10-30 depending on dataset size and API limits
  - Example: `--sample-size 30` sends 30 users, 30 groups, 30 computers, etc.

### Example

```bash
./ad-necromancer --data ./bloodhound-data --depth 10 --sample-size 15
```

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