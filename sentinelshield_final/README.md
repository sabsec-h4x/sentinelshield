# 🛡️ SentinelShield

**Advanced Intrusion Detection & Web Protection System**

SentinelShield is a security-focused web application that combines signature-based detection and machine learning to identify and block common web attacks in real time. It provides a modern dashboard for monitoring traffic, managing IPs, viewing logs, and generating security reports.

---

## 🚀 Features

- SQL Injection Detection
- Cross-Site Scripting (XSS) Detection
- Local File Inclusion (LFI) Detection
- Command Injection Detection
- Server-Side Request Forgery (SSRF) Detection
- Machine Learning Anomaly Detection
- GeoIP & Tor Exit Node Detection
- Real-time Security Dashboard
- IP Ban & Whitelist Management
- PDF Security Report Generation
- REST API using FastAPI

---

## 🏗️ System Architecture

```
                  Internet Users
                        │
                        ▼
                 ngrok Tunnel
                        │
                        ▼
              Flask Demo App (Port 5000)
                        │
                        ▼
             SentinelShield API (Port 8000)
                        │
        ┌────────────────────────────────┐
        │      Detection Pipeline        │
        │ • Request Parser               │
        │ • Rule Engine                  │
        │ • ML Anomaly Detector          │
        │ • GeoIP & Reputation Checker   │
        │ • Rate Limiter                 │
        │ • Decision Engine              │
        └────────────────────────────────┘
                        │
                        ▼
                SQLite Database
                        │
                        ▼
           React Dashboard (Port 3000)
```

---

## 🛠️ Technology Stack

### Backend
- Python
- FastAPI
- Flask
- SQLAlchemy
- SQLite

### Frontend
- React.js
- JavaScript
- HTML
- CSS

### Machine Learning
- Scikit-learn
- NumPy

### Additional Libraries
- Redis
- WebSockets
- ReportLab
- HTTPX

---

## 📂 Project Structure

```
sentinelshield/
│
├── backend/
│   ├── api/
│   ├── core/
│   ├── ml/
│   ├── models/
│   ├── reports/
│   ├── rules/
│   ├── tests/
│   └── main.py
│
├── sentinel_frontend/
│
├── sentinel_demoapp/
│
├── requirements.txt
│
└── README.md
```

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/sabsec-h4x/sentinelshield.git
cd sentinelshield
```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

or

```bash
pip install fastapi uvicorn sqlalchemy pydantic python-dotenv httpx scikit-learn numpy redis websockets reportlab flask
```

### Install Frontend Dependencies

```bash
cd sentinel_frontend
npm install
```

---

## ▶️ Running the Project

### Start Backend

```bash
cd backend
python -m uvicorn main:app --reload --port 8000
```

Backend URL

```
http://localhost:8000
```

API Documentation

```
http://localhost:8000/docs
```

---

### Start React Dashboard

```bash
cd sentinel_frontend
npm start
```

Dashboard URL

```
http://localhost:3000
```

---

### Start Demo Application

```bash
cd sentinel_demoapp
python realistic_app.py
```

Demo Application

```
http://localhost:5000
```

---

## 🧪 Detection Rules

| Attack Type | Rules | Severity |
|-------------|------:|-----------|
| SQL Injection | 8 | High |
| Cross-Site Scripting | 8 | High |
| Local File Inclusion | 5 | High |
| Command Injection | 5 | Critical |
| SSRF | 5 | High |
| **Total** | **31** | — |

---

## 📊 Available Modules

- Request Parser
- Rule Engine
- Machine Learning Detector
- GeoIP Detection
- Tor Detection
- Reputation Scoring
- Decision Engine
- Logging System
- IP Management
- Dashboard Analytics
- PDF Report Generator

---

## 📈 Future Enhancements

- Docker Deployment
- Kubernetes Support
- SIEM Integration
- Threat Intelligence Feed
- Email & Slack Notifications
- Cloud Deployment
- Multi-user Authentication

---

## 👨‍💻 Author

**Sabareeshwari S**

Cyber Security Student

---

## 📄 License

This project is developed for educational and research purposes.

MIT License

---

⭐ If you found this project useful, consider giving it a Star.
</div>
