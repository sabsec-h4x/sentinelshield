# ─────────────────────────────────────────────────────────────────
#  models/database.py — Database Tables & Connection
#
#  WHAT IS AN ORM?
#  ORM = Object-Relational Mapper. Instead of writing raw SQL like:
#     INSERT INTO logs (ip, verdict) VALUES ('1.2.3.4', 'BLOCK')
#  We write Python:
#     db.add(RequestLog(ip="1.2.3.4", verdict="BLOCK"))
#  SQLAlchemy handles the SQL translation for us.
#
#  TABLES WE CREATE:
#  1. request_logs  — every request the system inspects
#  2. alerts        — high-priority events (BLOCK verdicts)
#  3. banned_ips    — IPs that are permanently or temporarily banned
#  4. whitelist_ips — IPs that are always trusted
# ─────────────────────────────────────────────────────────────────

from sqlalchemy import (
    create_engine, Column, Integer, String,
    Float, Boolean, DateTime, Text, JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import sys
import os

# Add parent directory to path so we can import config
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config import DATABASE_URL

# ── Engine & Session Setup ────────────────────────────────────────
# The "engine" is the connection to the database
engine = create_engine(
    DATABASE_URL,
    # connect_args is only needed for SQLite (allows multiple threads)
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# A "session" is like a workspace — you open it, do work, then close it
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class — all our table models will inherit from this
Base = declarative_base()


# ── Table 1: Request Logs ─────────────────────────────────────────
class RequestLog(Base):
    """
    Every single request that passes through SentinelShield gets
    saved here — both clean and malicious ones.
    This is our main audit trail.
    """
    __tablename__ = "request_logs"

    id           = Column(Integer, primary_key=True, index=True)
    timestamp    = Column(DateTime, default=datetime.utcnow)

    # Request details
    ip_address   = Column(String(45), index=True)   # IPv6 can be up to 45 chars
    method       = Column(String(10))                # GET, POST, PUT, etc.
    path         = Column(String(2048))              # URL path
    query_string = Column(Text, nullable=True)       # ?param=value&...
    headers      = Column(JSON, nullable=True)       # Request headers as dict
    body         = Column(Text, nullable=True)       # POST body content
    user_agent   = Column(String(512), nullable=True)

    # Detection results
    verdict      = Column(String(10))               # ALLOW / FLAG / BLOCK
    threat_score = Column(Float, default=0.0)       # 0.0 to 100.0
    attack_types = Column(JSON, nullable=True)       # ["SQLi", "XSS"] etc.
    matched_rules= Column(JSON, nullable=True)       # Detailed rule matches
    is_anomaly   = Column(Boolean, default=False)    # ML zero-day detection

    # Geo & Reputation
    country_code = Column(String(5),  nullable=True)   # "US", "RU", "CN" etc.
    asn          = Column(String(100),nullable=True)   # Internet provider info
    is_tor       = Column(Boolean, default=False)
    is_vpn       = Column(Boolean, default=False)

    def __repr__(self):
        return f"<RequestLog id={self.id} ip={self.ip_address} verdict={self.verdict}>"


# ── Table 2: Alerts ───────────────────────────────────────────────
class Alert(Base):
    """
    Alerts are generated for high-severity events.
    Not every request becomes an alert — only the dangerous ones.
    These show up on the real-time dashboard.
    """
    __tablename__ = "alerts"

    id           = Column(Integer, primary_key=True, index=True)
    timestamp    = Column(DateTime, default=datetime.utcnow)
    log_id       = Column(Integer, index=True)       # Links to RequestLog
    ip_address   = Column(String(45), index=True)
    severity     = Column(String(10))                # LOW / MEDIUM / HIGH / CRITICAL
    attack_type  = Column(String(100))               # Primary attack category
    description  = Column(Text)                      # Human-readable explanation
    is_resolved  = Column(Boolean, default=False)    # Has an admin reviewed it?

    def __repr__(self):
        return f"<Alert id={self.id} severity={self.severity} type={self.attack_type}>"


# ── Table 3: Banned IPs ───────────────────────────────────────────
class BannedIP(Base):
    """
    IPs that have been banned — either manually by admin, or
    automatically after crossing the auto-ban threshold.
    """
    __tablename__ = "banned_ips"

    id           = Column(Integer, primary_key=True, index=True)
    ip_address   = Column(String(45), unique=True, index=True)
    reason       = Column(String(200))               # Why was it banned?
    banned_at    = Column(DateTime, default=datetime.utcnow)
    expires_at   = Column(DateTime, nullable=True)   # None = permanent ban
    is_permanent = Column(Boolean, default=False)
    banned_by    = Column(String(50), default="auto") # "auto" or admin username

    def __repr__(self):
        return f"<BannedIP {self.ip_address} permanent={self.is_permanent}>"


# ── Table 4: Whitelisted IPs ──────────────────────────────────────
class WhitelistedIP(Base):
    """
    Trusted IPs — these bypass all detection rules.
    Use for: your own office IP, monitoring tools, known partners.
    """
    __tablename__ = "whitelist_ips"

    id           = Column(Integer, primary_key=True, index=True)
    ip_address   = Column(String(45), unique=True, index=True)
    description  = Column(String(200))               # Why is this trusted?
    added_at     = Column(DateTime, default=datetime.utcnow)
    added_by     = Column(String(50), default="admin")

    def __repr__(self):
        return f"<WhitelistedIP {self.ip_address}>"


# ── Helper: Create All Tables ─────────────────────────────────────
def init_db():
    """Call this once at startup to create all tables in the database."""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully")


# ── Helper: Get a DB Session ──────────────────────────────────────
def get_db():
    """
    FastAPI dependency — provides a database session to each request.
    The 'finally' block ensures the session is ALWAYS closed,
    even if an error occurs during the request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
