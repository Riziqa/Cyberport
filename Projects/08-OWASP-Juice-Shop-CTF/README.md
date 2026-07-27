# 🧃 OWASP Juice Shop CTF Solver & Exploit Toolkit

Automated CTF challenge solver and exploit toolkit for **OWASP Juice Shop** — a modern intentionally vulnerable web application used for security training and penetration testing practice.

> ⚠️ **DISCLAIMER:** For **LOCAL LAB USE ONLY** against your own Juice Shop instance (`localhost:3000`). Never use against unauthorized targets.

## 🚀 Key Features

* **Autonomous CTF Solver:** Systematically solves Juice Shop challenges using API and browser-based exploits.
* **111 Challenge Coverage:** Targets all categories including SQL Injection, XSS, Path Traversal, Authentication Bypass, JWT Manipulation, and more.
* **Multi-Phase Attack Strategy:**
  * **Phase 1 — API Exploits:** Fast HTTP-based attacks (credential stuffing, SQLi, path traversal, API abuse)
  * **Phase 2 — Browser Exploits:** Playwright-based attacks for DOM XSS, UI manipulation, and client-side challenges
* **Complete Exploit Reference:** Documented command-by-command exploitation guide with 480+ exploit commands.

## 🔥 Attack Categories

| Category | Techniques |
|----------|-----------|
| **SQL Injection** | UNION-based credential dump, schema extraction, admin login bypass (`' OR 1=1--`) |
| **XSS (Reflected & Stored)** | Script injection via search, track-result, feedback forms, iframe/svg/img payloads |
| **Path Traversal** | FTP null-byte bypass (`%2500.md`), sensitive file access |
| **Authentication Bypass** | JWT manipulation, OAuth abuse, 2FA status probing |
| **IDOR** | User ID enumeration, forged feedback with spoofed UserId |
| **Miscellaneous** | Scoreboard discovery, metrics endpoint, robots.txt, easter eggs |

## 💻 Usage

```bash
# Start your local Juice Shop instance
docker run -p 3000:3000 bkimminich/juice-shop

# Run the autonomous solver
python juice_ctf_solver.py

# Run the flag hunter
python juice_flag_hunter.py

# Browser-based CTF challenges (requires Playwright)
python juice_browser_ctf.py
```

## 📂 Files

```
juice_ctf_solver.py          # Main autonomous CTF solver (345 lines)
juice_flag_hunter.py         # Targeted flag extraction tool
juice_browser_ctf.py         # Playwright-based browser exploit automation
juice_shop_exploits.md       # Complete 480+ command exploit reference
juice_shop_exploits.json     # Structured exploit data (machine-readable)
```

## 🏆 Results

Successfully solved challenges across all difficulty levels (⭐ to ⭐⭐⭐⭐⭐⭐) including:
- Admin login bypass via SQL injection
- Full user credential database dump
- Reflected & Stored XSS exploitation
- JWT token manipulation
- Path traversal with null-byte bypass
- IDOR exploitation via API parameter tampering
