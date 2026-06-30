# 🛡️ SentinelShield — Phase 4 Setup Guide

## What's in Phase 4

```
✅ PDF Report Generator     → Professional security reports with charts
✅ Webhook Alerts           → Slack, Discord, Email notifications
✅ Docker Deployment        → One command to run everything
✅ Report API Endpoint      → Generate reports from dashboard
```

---

## Step 1 — Install Phase 4 Dependencies

```powershell
pip install reportlab
```

---

## Step 2 — Copy Files Into Your Project

```
FROM: sentinel_phase4\reports\report_generator.py
TO:   sentinelshield_final\backend\reports\report_generator.py

FROM: sentinel_phase4\reports\reports_api.py
TO:   sentinelshield_final\backend\api\reports.py

FROM: sentinel_phase4\alerts\webhook_alerts.py
TO:   sentinelshield_final\backend\alerts\webhook_alerts.py
```

Create these new folders first:
```powershell
mkdir C:\sentinel_shield\sentinelshield_final\backend\reports
mkdir C:\sentinel_shield\sentinelshield_final\backend\alerts
mkdir C:\sentinel_shield\sentinelshield_final\backend\generated_reports
```

---

## Step 3 — Add Report Endpoint to main.py

Open `backend\main.py` and add these 2 lines:

```python
# Add this import (after existing imports):
from api.reports import router as reports_router

# Add this line (after existing app.include_router lines):
app.include_router(reports_router)
```

---

## Step 4 — Generate Your First PDF Report

Make sure backend is running, then run:

```powershell
cd C:\sentinel_shield\sentinelshield_final\backend
python reports\report_generator.py
```

Or via API:
```powershell
curl -X POST http://localhost:8000/api/reports/generate -H "Content-Type: application/json" -d "{\"hours\": 24}"
```

Opens a PDF with:
- Executive Summary
- Attack Type Breakdown Table
- Top Attacking IPs
- Recent Attack Timeline
- Security Recommendations

---

## Step 5 — Configure Slack/Discord Alerts (Optional)

Create a `.env` file in `sentinelshield_final\backend\`:

```env
# Slack Webhook (get from: api.slack.com/messaging/webhooks)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Discord Webhook (get from: Server Settings → Integrations → Webhooks)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK/URL

# Email Alerts (Gmail example)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=youremail@gmail.com
EMAIL_PASS=your_app_password
EMAIL_TO=security@yourcompany.com
```

Test your alerts:
```powershell
python alerts\webhook_alerts.py
```

---

## Step 6 — Docker Deployment (Advanced)

Install Docker Desktop from: https://www.docker.com/products/docker-desktop

Then run everything with ONE command:
```powershell
cd C:\sentinel_shield
docker-compose -f sentinel_phase4\docker\docker-compose.yml up
```

This starts:
- Backend at http://localhost:8000
- Frontend at http://localhost:3000
- Redis at localhost:6379

Stop everything:
```powershell
docker-compose down
```

---

## Final Project Structure (All 4 Phases)

```
sentinelshield_final\backend\
├── main.py
├── config.py
├── core\
│   ├── parser.py
│   ├── rule_engine.py
│   ├── decision_engine.py
│   ├── rate_limiter.py       ← Phase 2
│   └── geo_reputation.py     ← Phase 2
├── ml\
│   └── anomaly_detector.py   ← Phase 2
├── models\
│   └── database.py
├── api\
│   ├── inspect.py
│   ├── logs.py
│   └── reports.py            ← Phase 4
├── rules\
│   └── *.json (5 files)
├── reports\
│   └── report_generator.py   ← Phase 4
├── alerts\
│   └── webhook_alerts.py     ← Phase 4
└── tests\
    └── attack_simulator.py
```

---

## Complete Feature Summary

| Phase | Features |
|---|---|
| Phase 1 ✅ | Rule engine, 31 signatures, SQLite, auto-ban, REST API |
| Phase 2 ✅ | ML zero-day, GeoIP, Tor detection, rate limiting |
| Phase 3 ✅ | React dashboard, live feed, charts, IP manager, tester |
| Phase 4 ✅ | PDF reports, Slack/Discord alerts, Docker deployment |
