# ─────────────────────────────────────────────────────────────────
#  config.py — Central Configuration for SentinelShield
#
#  WHY THIS FILE EXISTS:
#  Instead of hardcoding values like database paths, thresholds,
#  and settings all over the codebase, we put them all here.
#  If you want to change a setting, you only change it in ONE place.
# ─────────────────────────────────────────────────────────────────

import os
from dotenv import load_dotenv

# Load variables from a .env file (if it exists)
# This lets you keep secrets out of your code
load_dotenv()

# ── Database ──────────────────────────────────────────────────────
# SQLite = a simple file-based database, perfect for development
# In production you'd swap this for PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelshield.db")

# ── Rate Limiting ─────────────────────────────────────────────────
# How many requests can one IP make before we consider it suspicious?
RATE_LIMIT_REQUESTS   = int(os.getenv("RATE_LIMIT_REQUESTS",  "100"))  # max requests
RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))  # per 60 seconds

# ── Auto-Ban Settings ─────────────────────────────────────────────
# After how many BLOCK verdicts should an IP be auto-banned?
AUTO_BAN_THRESHOLD     = int(os.getenv("AUTO_BAN_THRESHOLD",  "5"))
# How long should an auto-ban last (in seconds)?  86400 = 24 hours
AUTO_BAN_DURATION_SEC  = int(os.getenv("AUTO_BAN_DURATION_SEC", "86400"))

# ── Scoring Thresholds ────────────────────────────────────────────
# Threat score is 0–100. These thresholds decide the verdict.
SCORE_FLAG_THRESHOLD  = int(os.getenv("SCORE_FLAG_THRESHOLD",  "30"))  # FLAG  if score >= 30
SCORE_BLOCK_THRESHOLD = int(os.getenv("SCORE_BLOCK_THRESHOLD", "60"))  # BLOCK if score >= 60

# ── ML Anomaly Detection ──────────────────────────────────────────
# Contamination = expected % of anomalies in training data (0.05 = 5%)
ML_CONTAMINATION = float(os.getenv("ML_CONTAMINATION", "0.05"))
# Path to the saved ML model file
ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "./ml/model.pkl")

# ── Redis (Rate Limiter) ──────────────────────────────────────────
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB   = int(os.getenv("REDIS_DB",   "0"))

# ── Rules Directory ───────────────────────────────────────────────
# Where are the JSON rule files stored?
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# ── App Settings ──────────────────────────────────────────────────
APP_NAME    = "SentinelShield"
APP_VERSION = "1.0.0"
DEBUG_MODE  = os.getenv("DEBUG", "true").lower() == "true"
