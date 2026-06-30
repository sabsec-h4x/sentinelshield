# ─────────────────────────────────────────────────────────────────
#  demo_app.py — A Real Web App Protected by SentinelShield
#
#  HOW IT WORKS:
#  Every request that hits this app AUTOMATICALLY goes through
#  SentinelShield first. Clean requests pass through.
#  Attacks get blocked before reaching the app.
#
#  HOW TO RUN:
#    pip install flask
#    python demo_app.py
#    Open: http://localhost:5000
#
#  MAKE SURE SentinelShield backend is running on port 8000 first!
# ─────────────────────────────────────────────────────────────────

from flask import Flask, request, jsonify, render_template_string, redirect
import httpx
import json

app = Flask(__name__)

# ── SentinelShield Middleware ─────────────────────────────────────
# This runs BEFORE every single request to this app
# It sends the request to SentinelShield for inspection
# If BLOCK → returns 403 immediately
# If ALLOW/FLAG → lets the request through to the app

SENTINEL_URL = "http://localhost:8000/api/inspect"

@app.before_request
def sentinel_check():
    """
    This function runs automatically before EVERY request.
    It's the bridge between this app and SentinelShield.
    """
    # Skip checking static files (CSS, JS, images)
    if request.path.startswith('/static'):
        return None

    # Get the real client IP
    # X-Forwarded-For is used when behind a proxy/ngrok
    ip = (
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        or request.headers.get('X-Real-IP', '')
        or request.remote_addr
        or '127.0.0.1'
    )

    try:
        # Send request details to SentinelShield for inspection
        result = httpx.post(
            SENTINEL_URL,
            json={
                "ip":      ip,
                "method":  request.method,
                "path":    request.path,
                "query":   request.query_string.decode('utf-8', errors='replace'),
                "headers": dict(request.headers),
                "body":    request.get_data(as_text=True) or None,
            },
            timeout=3.0  # Don't wait more than 3 seconds
        )
        data = result.json()

        verdict = data.get('verdict', 'ALLOW')
        score   = data.get('threat_score', 0)
        attacks = data.get('attack_types', [])
        geo     = data.get('geo', {})

        # BLOCK → return 403 immediately, never reaches the app
        if verdict == 'BLOCK':
            return render_template_string(BLOCK_PAGE,
                ip          = ip,
                score       = score,
                attacks     = ', '.join(attacks) if attacks else 'Security violation',
                country     = geo.get('country_name', 'Unknown'),
                request_id  = data.get('request_id', 0),
                is_tor      = geo.get('is_tor', False),
                is_anomaly  = data.get('is_anomaly', False),
            ), 403

        # FLAG → allow through but log it (already logged by SentinelShield)
        # ALLOW → pass through normally

    except Exception as e:
        # If SentinelShield is down, allow requests (fail open)
        # In production you might want to fail closed (block all)
        print(f"⚠️  SentinelShield unavailable: {e} — allowing request")

    return None  # None = continue to the actual route


# ── Block Page HTML ───────────────────────────────────────────────
BLOCK_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked — SentinelShield</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background: #050510;
            color: #c0c0d0;
            font-family: 'Courier New', monospace;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container {
            text-align: center;
            max-width: 600px;
            padding: 40px;
            background: #0a0a1a;
            border: 1px solid #ff4d4d44;
            border-radius: 12px;
            box-shadow: 0 0 40px #ff4d4d22;
        }
        .shield { font-size: 60px; margin-bottom: 16px; }
        h1 { color: #ff4d4d; font-size: 28px; letter-spacing: 4px; margin-bottom: 8px; }
        .subtitle { color: #556; font-size: 12px; letter-spacing: 2px; margin-bottom: 30px; }
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 24px;
            text-align: left;
        }
        .info-card {
            background: #050510;
            border: 1px solid #1a1a3e;
            border-radius: 6px;
            padding: 12px;
        }
        .info-label { font-size: 9px; color: #334; letter-spacing: 2px; margin-bottom: 4px; }
        .info-value { font-size: 13px; color: #ff4d4d; }
        .reason { font-size: 12px; color: #778; margin-bottom: 24px; line-height: 1.6; }
        .back-btn {
            display: inline-block;
            background: #1a1a2e;
            border: 1px solid #334;
            color: #778;
            padding: 10px 24px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 12px;
            letter-spacing: 2px;
        }
        .badge {
            display: inline-block;
            font-size: 10px;
            padding: 3px 8px;
            border-radius: 3px;
            margin: 4px;
            border: 1px solid;
        }
        .tor-badge { color: #00ccff; background: #00ccff15; border-color: #00ccff33; }
        .ml-badge  { color: #cc44ff; background: #cc44ff15; border-color: #cc44ff33; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>ACCESS BLOCKED</h1>
        <div class="subtitle">SENTINELSHIELD INTRUSION DETECTION SYSTEM</div>

        <div class="info-grid">
            <div class="info-card">
                <div class="info-label">YOUR IP ADDRESS</div>
                <div class="info-value">{{ ip }}</div>
            </div>
            <div class="info-card">
                <div class="info-label">THREAT SCORE</div>
                <div class="info-value">{{ score }}/100</div>
            </div>
            <div class="info-card">
                <div class="info-label">ATTACK TYPE</div>
                <div class="info-value" style="color:#ff9900;">{{ attacks }}</div>
            </div>
            <div class="info-card">
                <div class="info-label">YOUR LOCATION</div>
                <div class="info-value" style="color:#778;">{{ country }}</div>
            </div>
        </div>

        {% if is_tor %}
        <span class="badge tor-badge">🧅 TOR EXIT NODE</span>
        {% endif %}
        {% if is_anomaly %}
        <span class="badge ml-badge">🤖 ML ANOMALY</span>
        {% endif %}

        <p class="reason">
            Your request has been identified as potentially malicious and has been
            blocked by our Web Application Firewall. This incident has been logged
            and reported. Reference ID: #{{ request_id }}
        </p>

        <a href="/" class="back-btn">← GO BACK</a>
    </div>
</body>
</html>
"""


# ── Main Page ─────────────────────────────────────────────────────
@app.route('/')
def home():
    ip = request.headers.get('X-Forwarded-For','').split(',')[0].strip() or request.remote_addr
    return render_template_string(HOME_PAGE, ip=ip)


# ── Login Page (vulnerable target for testing) ────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        # Simulate login (NOT real authentication — for demo only)
        if username == 'admin' and password == 'password123':
            return render_template_string(SUCCESS_PAGE, user=username)
        return render_template_string(LOGIN_PAGE, error="Invalid credentials")
    return render_template_string(LOGIN_PAGE, error=None)


# ── Search Page (vulnerable target for XSS testing) ───────────────
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string(SEARCH_PAGE, query=query)


# ── Profile Page (vulnerable to path traversal testing) ──────────
@app.route('/profile')
def profile():
    user_id = request.args.get('id', '1')
    return render_template_string(PROFILE_PAGE, user_id=user_id)


# ── API endpoint (vulnerable to injection) ────────────────────────
@app.route('/api/data')
def api_data():
    item_id = request.args.get('id', '1')
    return jsonify({
        "id":      item_id,
        "name":    "Sample Product",
        "price":   29.99,
        "status":  "active"
    })


# ── Status endpoint ───────────────────────────────────────────────
@app.route('/status')
def status():
    return jsonify({
        "app":       "SentinelShield Demo App",
        "protected": True,
        "sentinel":  "http://localhost:8000",
        "dashboard": "http://localhost:3000",
    })


# ── Page Templates ────────────────────────────────────────────────
HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Demo Shop — Protected by SentinelShield</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#f8f9fa; font-family:Arial,sans-serif; color:#333; }
        header {
            background:#1a1a2e;
            color:#fff;
            padding:16px 40px;
            display:flex;
            justify-content:space-between;
            align-items:center;
        }
        .logo { font-size:22px; font-weight:bold; }
        .badge {
            background:#00ff9922;
            border:1px solid #00ff9944;
            color:#00ff99;
            padding:4px 12px;
            border-radius:20px;
            font-size:12px;
        }
        .hero {
            background:linear-gradient(135deg,#1a1a2e,#0d0d1a);
            color:#fff;
            padding:60px 40px;
            text-align:center;
        }
        .hero h1 { font-size:36px; margin-bottom:12px; }
        .hero p  { color:#888; font-size:16px; margin-bottom:30px; }
        .nav-links { display:flex; gap:12px; justify-content:center; flex-wrap:wrap; }
        .nav-links a {
            background:#1a1a3e;
            color:#c0c0ff;
            padding:10px 20px;
            border-radius:6px;
            text-decoration:none;
            border:1px solid #2a2a5e;
            transition:all 0.2s;
        }
        .nav-links a:hover { background:#2a2a5e; }
        .container { max-width:900px; margin:40px auto; padding:0 20px; }
        .card-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:20px; margin-bottom:30px; }
        .card {
            background:#fff;
            border-radius:8px;
            padding:20px;
            box-shadow:0 2px 8px rgba(0,0,0,0.08);
            border:1px solid #eee;
        }
        .card h3 { margin-bottom:8px; color:#1a1a2e; }
        .card p  { font-size:13px; color:#777; margin-bottom:12px; }
        .card a  { color:#0044cc; font-size:13px; text-decoration:none; }
        .info-bar {
            background:#fff3cd;
            border:1px solid #ffc107;
            border-radius:6px;
            padding:12px 20px;
            font-size:13px;
            color:#856404;
            margin-bottom:20px;
        }
        .attack-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }
        .attack-card {
            background:#fff;
            border:1px solid #eee;
            border-radius:6px;
            padding:16px;
        }
        .attack-card h4 { color:#cc2222; margin-bottom:6px; font-size:14px; }
        .attack-card code {
            display:block;
            background:#f5f5f5;
            padding:6px 10px;
            border-radius:4px;
            font-size:11px;
            color:#333;
            margin:4px 0;
            word-break:break-all;
        }
        .attack-card a {
            display:inline-block;
            margin-top:6px;
            background:#cc2222;
            color:#fff;
            padding:4px 10px;
            border-radius:4px;
            font-size:11px;
            text-decoration:none;
        }
        footer {
            background:#1a1a2e;
            color:#556;
            text-align:center;
            padding:20px;
            font-size:12px;
            margin-top:40px;
        }
        .shield-badge {
            display:inline-block;
            background:#00ff9911;
            border:1px solid #00ff9933;
            color:#00ff99;
            padding:3px 10px;
            border-radius:20px;
            font-size:11px;
        }
    </style>
</head>
<body>

<header>
    <div class="logo">🛒 DemoShop</div>
    <div style="display:flex;gap:12px;align-items:center;">
        <span style="color:#888;font-size:12px;">Your IP: <strong style="color:#fff;">{{ ip }}</strong></span>
        <span class="badge">🛡️ Protected by SentinelShield</span>
    </div>
</header>

<div class="hero">
    <h1>Welcome to DemoShop</h1>
    <p>This app is protected by SentinelShield WAF — every request is inspected in real time</p>
    <div class="nav-links">
        <a href="/login">🔑 Login Page</a>
        <a href="/search?q=shoes">🔍 Search</a>
        <a href="/profile?id=1">👤 Profile</a>
        <a href="/api/data?id=1">⚙️ API</a>
        <a href="http://localhost:3000" target="_blank">📊 Dashboard</a>
        <a href="http://localhost:8000/docs" target="_blank">📚 API Docs</a>
    </div>
</div>

<div class="container">

    <div class="info-bar">
        ℹ️ <strong>Testing Instructions:</strong> Click any attack link below.
        Clean requests → ✅ ALLOW. Attack requests → 🚫 BLOCK page appears.
        Watch the <a href="http://localhost:3000" target="_blank">Dashboard</a> update in real time!
    </div>

    <!-- Normal pages -->
    <h2 style="margin-bottom:16px;color:#1a1a2e;">🟢 Normal Pages (will ALLOW)</h2>
    <div class="card-grid">
        <div class="card">
            <h3>🔑 Login</h3>
            <p>Normal login form — SentinelShield will allow this</p>
            <a href="/login">Visit Login →</a>
        </div>
        <div class="card">
            <h3>🔍 Search</h3>
            <p>Normal product search — will be allowed through</p>
            <a href="/search?q=blue+running+shoes">Search Shoes →</a>
        </div>
        <div class="card">
            <h3>👤 Profile</h3>
            <p>Normal user profile — clean request allowed</p>
            <a href="/profile?id=42">View Profile →</a>
        </div>
    </div>

    <!-- Attack tests -->
    <h2 style="margin-bottom:16px;color:#cc2222;">🔴 Attack Tests (will BLOCK)</h2>
    <div class="attack-grid">

        <div class="attack-card">
            <h4>💉 SQL Injection</h4>
            <code>/login?username=admin'--</code>
            <code>/search?q=1 UNION SELECT * FROM users--</code>
            <a href="/login?username=admin'--&password=x">Test SQLi →</a>
        </div>

        <div class="attack-card">
            <h4>🖥️ XSS Attack</h4>
            <code>/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code>
            <code>/profile?name=&lt;img onerror=alert(1)&gt;</code>
            <a href="/search?q=<script>alert(document.cookie)</script>">Test XSS →</a>
        </div>

        <div class="attack-card">
            <h4>📁 Path Traversal</h4>
            <code>/profile?id=../../etc/passwd</code>
            <code>/api/data?file=../config.py</code>
            <a href="/profile?id=../../../../etc/passwd">Test LFI →</a>
        </div>

        <div class="attack-card">
            <h4>⚡ Command Injection</h4>
            <code>/api/data?id=1;cat /etc/shadow</code>
            <code>/search?q=shoes|whoami</code>
            <a href="/api/data?id=1;cat /etc/passwd">Test CMDi →</a>
        </div>

        <div class="attack-card">
            <h4>🌐 SSRF Attack</h4>
            <code>/api/data?url=http://169.254.169.254</code>
            <code>/search?q=http://localhost:6379</code>
            <a href="/api/data?url=http://169.254.169.254/latest/meta-data/">Test SSRF →</a>
        </div>

        <div class="attack-card">
            <h4>🤖 Zero-Day (ML)</h4>
            <code>/search?q=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</code>
            <code>Unusual pattern — no matching rule</code>
            <a href="/search?q=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">Test ML →</a>
        </div>

    </div>

</div>

<footer>
    DemoShop v1.0 — Protected by SentinelShield v2.0 |
    Dashboard: <a href="http://localhost:3000" style="color:#5577ff;">localhost:3000</a> |
    API: <a href="http://localhost:8000/docs" style="color:#5577ff;">localhost:8000/docs</a>
</footer>

</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login — DemoShop</title>
    <style>
        body { background:#f0f2f5; font-family:Arial,sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }
        .box { background:#fff; padding:40px; border-radius:10px; box-shadow:0 4px 20px rgba(0,0,0,0.1); width:380px; }
        h2 { color:#1a1a2e; margin-bottom:8px; }
        .subtitle { color:#888; font-size:13px; margin-bottom:24px; }
        label { display:block; font-size:13px; color:#555; margin-bottom:4px; }
        input { width:100%; padding:10px; border:1px solid #ddd; border-radius:5px; margin-bottom:16px; font-size:14px; box-sizing:border-box; }
        button { width:100%; background:#1a1a2e; color:#fff; padding:12px; border:none; border-radius:5px; font-size:14px; cursor:pointer; }
        .error { background:#fff5f5; border:1px solid #ffcccc; color:#cc2222; padding:10px; border-radius:5px; margin-bottom:16px; font-size:13px; }
        .badge { display:inline-block; background:#00ff9911; border:1px solid #00ff9933; color:#00ff99; padding:3px 10px; border-radius:20px; font-size:11px; margin-bottom:20px; }
        a { color:#0044cc; font-size:13px; }
    </style>
</head>
<body>
<div class="box">
    <h2>🔑 Login</h2>
    <div class="subtitle">DemoShop Account</div>
    <span class="badge">🛡️ Protected by SentinelShield</span>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    <form method="POST">
        <label>Username</label>
        <input type="text" name="username" placeholder="admin" />
        <label>Password</label>
        <input type="password" name="password" placeholder="password123" />
        <button type="submit">Login</button>
    </form>
    <p style="margin-top:16px;text-align:center;"><a href="/">← Back to Home</a></p>
    <hr style="margin:16px 0;border-color:#eee;">
    <p style="font-size:12px;color:#999;">Test credentials: admin / password123</p>
</div>
</body>
</html>
"""

SEARCH_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Search — DemoShop</title>
    <style>
        body { background:#f0f2f5; font-family:Arial,sans-serif; max-width:700px; margin:40px auto; padding:0 20px; }
        .search-box { background:#fff; padding:24px; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.08); margin-bottom:20px; }
        input { width:70%; padding:10px; border:1px solid #ddd; border-radius:5px; font-size:14px; }
        button { background:#1a1a2e; color:#fff; padding:10px 20px; border:none; border-radius:5px; cursor:pointer; margin-left:8px; }
        .result { background:#fff; padding:16px; border-radius:8px; border:1px solid #eee; margin-bottom:12px; }
        .badge { display:inline-block; background:#00ff9911; border:1px solid #00ff9933; color:#00ff99; padding:3px 10px; border-radius:20px; font-size:11px; }
        a { color:#0044cc; font-size:13px; }
    </style>
</head>
<body>
    <h2>🔍 Product Search <span class="badge">🛡️ Protected</span></h2>
    <div class="search-box">
        <form method="GET">
            <input name="q" value="{{ query }}" placeholder="Search products..." />
            <button type="submit">Search</button>
        </form>
    </div>
    {% if query %}
    <div class="result"><strong>Results for:</strong> {{ query }}</div>
    <div class="result">👟 Blue Running Shoes — $49.99</div>
    <div class="result">👟 Red Sports Sneakers — $59.99</div>
    {% endif %}
    <p><a href="/">← Back to Home</a></p>
</body>
</html>
"""

PROFILE_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Profile — DemoShop</title>
    <style>
        body { background:#f0f2f5; font-family:Arial,sans-serif; max-width:600px; margin:40px auto; padding:0 20px; }
        .card { background:#fff; padding:24px; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
        .badge { display:inline-block; background:#00ff9911; border:1px solid #00ff9933; color:#00ff99; padding:3px 10px; border-radius:20px; font-size:11px; }
        a { color:#0044cc; font-size:13px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>👤 User Profile <span class="badge">🛡️ Protected</span></h2>
        <p><strong>User ID:</strong> {{ user_id }}</p>
        <p><strong>Name:</strong> Demo User</p>
        <p><strong>Email:</strong> user@demoshop.com</p>
        <p><strong>Role:</strong> Customer</p>
        <br>
        <a href="/">← Back to Home</a>
    </div>
</body>
</html>
"""

SUCCESS_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Welcome!</title>
<style>body{font-family:Arial,sans-serif;text-align:center;padding:60px;background:#f0f2f5;} .box{background:#fff;padding:40px;border-radius:8px;display:inline-block;box-shadow:0 2px 8px rgba(0,0,0,0.1);}</style>
</head>
<body>
<div class="box">
    <h1>✅ Welcome, {{ user }}!</h1>
    <p>Login successful. You're in the protected area.</p>
    <br><a href="/">← Back to Home</a>
</div>
</body>
</html>
"""


if __name__ == '__main__':
    print("\n" + "="*55)
    print("  🛒 DemoShop — Protected by SentinelShield")
    print("="*55)
    print("  App running at:  http://localhost:5000")
    print("  Dashboard at:    http://localhost:3000")
    print("  Make sure SentinelShield is running on port 8000!")
    print("="*55 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0')
