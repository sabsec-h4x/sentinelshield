# ─────────────────────────────────────────────────────────────────
#  main.py — SentinelShield FastAPI Application Entry Point
#
#  HOW TO RUN:
#    cd backend
#    uvicorn main:app --reload --port 8000
#
#  THEN VISIT:
#    API Docs:  http://localhost:8000/docs   ← Interactive Swagger UI
#    API Spec:  http://localhost:8000/redoc
#    Health:    http://localhost:8000/health
# ─────────────────────────────────────────────────────────────────

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sys, os

# Make sure Python can find our modules
sys.path.append(os.path.dirname(__file__))

from config import APP_NAME, APP_VERSION, DEBUG_MODE
from models.database import init_db
from core.rule_engine import rule_engine
from api.inspect import router as inspect_router
from api.logs    import router as logs_router

# ── Create FastAPI App ────────────────────────────────────────────
app = FastAPI(
    title       = APP_NAME,
    description = "Advanced Intrusion Detection & Web Protection System",
    version     = APP_VERSION,
    docs_url    = "/docs",    # Swagger UI — interactive API docs
    redoc_url   = "/redoc",   # ReDoc UI — alternative docs
)

# ── CORS Middleware ───────────────────────────────────────────────
# CORS = Cross-Origin Resource Sharing
# This allows our React frontend (running on port 3000) to call
# our FastAPI backend (running on port 8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Register API Routers ──────────────────────────────────────────
# Routers are like "modules" that group related endpoints
app.include_router(inspect_router)
app.include_router(logs_router)

# ── Startup Event ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    """
    This runs ONCE when the server starts.
    Use it to: create database tables, load ML models, etc.
    """
    print("\n" + "="*55)
    print(f"  🛡️  {APP_NAME} v{APP_VERSION} starting...")
    print("="*55)

    # Create database tables
    init_db()

    # Load all detection rules into memory
    rule_engine.load_rules()

    print("="*55)
    print(f"  ✅ Server ready at http://localhost:8000")
    print(f"  📚 API Docs at  http://localhost:8000/docs")
    print("="*55 + "\n")


# ── Health Check ──────────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health_check():
    """Quick check to see if the server is running."""
    return {
        "status":  "online",
        "app":     APP_NAME,
        "version": APP_VERSION,
    }


# ── Root ──────────────────────────────────────────────────────────
@app.get("/", tags=["System"])
def root():
    return {
        "message": f"Welcome to {APP_NAME}",
        "docs":    "/docs",
        "version": APP_VERSION,
    }
