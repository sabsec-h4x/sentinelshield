# ─────────────────────────────────────────────────────────────────
#  tests/test_phase2.py — Phase 2 Feature Tests
#
#  Tests all 3 new Phase 2 features:
#  1. ML Zero-Day Detection
#  2. Rate Limiting
#  3. GeoIP Reputation
#
#  HOW TO RUN:
#    python tests/test_phase2.py
# ─────────────────────────────────────────────────────────────────

import httpx
import time
import json

BASE_URL = "http://localhost:8000"


def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def send(ip, query, label="", method="GET", path="/test", body=None):
    resp = httpx.post(f"{BASE_URL}/api/inspect", json={
        "ip": ip, "method": method, "path": path,
        "query": query, "headers": {}, "body": body
    }, timeout=10)
    data = resp.json()
    verdict = data.get("verdict", "ERROR")
    score   = data.get("threat_score", 0)
    anomaly = data.get("is_anomaly", False)
    geo     = data.get("geo", {})

    icon = "✅" if verdict == "ALLOW" else ("⚠️ " if verdict == "FLAG" else "🚫")
    print(f"\n  {icon} {label}")
    print(f"     Verdict:  {verdict}  |  Score: {score}  |  Anomaly: {anomaly}")
    if geo:
        print(f"     Country:  {geo.get('country_name','?')} ({geo.get('country_code','?')})")
        print(f"     Tor: {geo.get('is_tor',False)}  |  Datacenter: {geo.get('is_datacenter',False)}")
    if data.get("matches"):
        for m in data["matches"]:
            print(f"     Rule: {m['rule_name']} (+{m['score']}pts)")
    return data


# ─── TEST 1: ML Zero-Day Detection ───────────────────────────────
separator("TEST 1 — ML Zero-Day Detection")
print("  These payloads have NO matching rules")
print("  ML should flag them as anomalous\n")

# Normal request — should be ALLOW
send("50.0.0.1", "id=42&page=1", label="Normal request (should ALLOW)")

# Heavily encoded payload — no rule matches but ML should flag it
send("50.0.0.2", "%61%64%6d%69%6e%27%2d%2d%20%4f%52%20%31%3d%31",
     label="Heavy URL encoding — ML anomaly test")

# Very long repetitive string — fuzzing pattern
send("50.0.0.3", "x=" + "A"*80,
     label="Fuzzing payload (repetitive chars) — ML anomaly test")

# Weird mix of special chars with no rule match
send("50.0.0.4", "data=\x00\x01\x02normal_text_here",
     label="Non-printable chars mixed in — ML anomaly test")


# ─── TEST 2: Rate Limiting ────────────────────────────────────────
separator("TEST 2 — Rate Limiting (sends 15 rapid requests)")
print("  Sending 15 requests rapidly from same IP")
print("  Should trigger rate limit after threshold\n")

rate_ip = "99.0.0.1"
for i in range(15):
    resp = httpx.post(f"{BASE_URL}/api/inspect", json={
        "ip": rate_ip, "method": "GET",
        "path": "/login", "query": f"attempt={i}",
        "headers": {}
    })
    data    = resp.json()
    verdict = data.get("verdict")
    limited = data.get("rate_limited", False)
    print(f"  Request {i+1:02d}: {verdict} | Rate limited: {limited}")

# Check rate stats for that IP
print(f"\n  Checking rate stats for {rate_ip}:")
stats = httpx.get(f"{BASE_URL}/api/rate-stats/{rate_ip}").json()
print(f"  → {json.dumps(stats, indent=4)}")


# ─── TEST 3: GeoIP + Reputation ──────────────────────────────────
separator("TEST 3 — GeoIP + Reputation Scoring")
print("  Testing IPs from known suspicious ranges\n")

# Known Tor range indicator
send("185.220.101.50", "page=1",
     label="Tor exit node range IP")

# Datacenter range
send("54.162.100.50", "id=5",
     label="AWS datacenter IP")

# Normal residential-looking IP
send("72.21.202.5", "search=shoes",
     label="Normal residential IP")


# ─── TEST 4: Combined Attack + Geo ───────────────────────────────
separator("TEST 4 — SQLi from Tor Exit Node (worst case)")

send("185.220.101.99",
     "id=1' UNION SELECT username,password FROM users--",
     label="SQLi from Tor exit node — should get max score")


# ─── ML STATUS ───────────────────────────────────────────────────
separator("ML MODEL STATUS")
status = httpx.get(f"{BASE_URL}/api/ml/status").json()
print(f"\n  ML Available:     {status.get('ml_available')}")
print(f"  Model File:       {status.get('model_file_exists')}")


print("\n" + "="*60)
print("  Phase 2 Tests Complete!")
print("  Check /api/stats for full attack summary")
print("="*60 + "\n")
