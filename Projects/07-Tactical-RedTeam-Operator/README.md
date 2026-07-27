# 🤖 Tactical — Autonomous Red-Team Operator CLI

**Tactical** is an autonomous AI-driven red-team operator CLI that connects to local LLM models (via Ollama), gives the AI tool definitions (bash execution, file operations, web search, exploit-db), and runs autonomous attack chains with streaming feedback, anti-hang protection, and battle-tested exploit knowledge.

> ⚠️ **DISCLAIMER:** This tool is for **authorized local lab testing and educational research ONLY**. Tested against Metasploitable 2 VMs in isolated local networks.

## 🚀 Key Features

* **Autonomous Attack Chains:** AI reasons about targets, selects tools, executes scans and exploits, and iterates until objectives are met.
* **6 Built-In Tools:** `run_bash` (shell commands), `read_file`, `write_file`, `search_web` (DuckDuckGo), `exploit_search` (searchsploit), `mitre_search` (MITRE ATT&CK).
* **4-Layer Anti-Hang System:** Semantic hang detection (60% word overlap), tool-pair loop detection, auto-blacklist on 3 identical failures, hard abort on 3 global anti-hang events.
* **Knowledge Sandwich Architecture:** System prompt playbook → OSCP cheatsheet → MITRE ATT&CK → Live web search for CVEs/PoCs.
* **Session Management:** Save, resume, list, and export attack sessions as markdown reports.
* **52 Unit Tests:** Tested against 4 local lab targets — 2 ROOT shells confirmed on Metasploitable 2.

## 🏗️ Architecture

```
User input → Classify → [LLM Chat (Ollama)] → Detect tool_calls
              ↓                                        ↓
         Question → text              Execute tool (nmap, metasploit, curl...)
                                                       ↓
                                                Feed result back → Loop until done
```

## 🛡️ Skills & Sub-Agents

| Skill | Description |
|-------|-------------|
| `scanner` | Broad-spectrum code/network scanner, sharded sweep for candidate nodes |
| `exploit/web` | Web exploitation routing: SQLi, XSS, SSRF, LFI, SSTI, IDOR, Command Injection |
| `exploit/ad` | Active Directory exploitation workflows |
| `recon` | Reconnaissance and target enumeration |
| `reverser` | Binary reverse engineering and analysis |
| `vulnresearch` | Vulnerability research and CVE analysis |

## 💻 Usage

```bash
# Interactive mode
python3 tactical.py

# One-shot mission against local lab target
python3 tactical.py "recon 192.168.40.128"

# Use specific model
python3 tactical.py --model tactical:32b "exploit vsftpd on 192.168.40.128"
```

## 📊 Lab Results

* **Metasploitable 2 (192.168.40.128):** Full Nmap scan → vsftpd 2.3.4 backdoor exploitation → ROOT shell obtained
* **Local Network Router (192.168.1.1):** Service enumeration and vulnerability assessment
* **Custom Targets:** RF infrastructure analysis and enumeration

## 📂 Key Files

```
tactical.py          # Main 920-line autonomous operator engine
skills/              # 18 specialized skill modules
  scanner/           # Network & code scanning playbook
  exploit/web/       # Web exploitation sub-skills (SQLi, XSS, SSRF...)
  exploit/ad/        # Active Directory attack playbooks
  recon/             # Reconnaissance workflows
  reverser/          # Binary RE analysis
config/              # Model configurations
tests/               # 52 unit tests
```
