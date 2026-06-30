# ─────────────────────────────────────────────────────────────────
#  api/logs.py — Logs & Stats Endpoints
#
#  ENDPOINTS:
#  GET /api/logs          — List all request logs (with filters)
#  GET /api/logs/{id}     — Get a single log entry
#  GET /api/alerts        — List all alerts
#  GET /api/stats         — Dashboard summary statistics
#  GET /api/rules         — List all loaded detection rules
#  POST /api/ban          — Manually ban an IP
#  DELETE /api/ban/{ip}   — Unban an IP
#  POST /api/whitelist    — Add IP to whitelist
# ─────────────────────────────────────────────────────────────────

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from models.database import get_db, RequestLog, Alert, BannedIP, WhitelistedIP
from core.rule_engine import rule_engine

router = APIRouter(prefix="/api", tags=["Logs & Management"])


# ── GET /api/logs ─────────────────────────────────────────────────

@router.get("/logs")
def get_logs(
    page:     int = Query(default=1,  ge=1,     description="Page number"),
    limit:    int = Query(default=50, le=500,   description="Results per page"),
    verdict:  Optional[str] = Query(default=None, description="Filter by verdict: ALLOW/FLAG/BLOCK"),
    ip:       Optional[str] = Query(default=None, description="Filter by IP address"),
    category: Optional[str] = Query(default=None, description="Filter by attack category"),
    db: Session = Depends(get_db)
):
    """Get paginated request logs with optional filters."""
    query = db.query(RequestLog)

    if verdict:
        query = query.filter(RequestLog.verdict == verdict.upper())
    if ip:
        query = query.filter(RequestLog.ip_address == ip)

    total = query.count()
    logs  = query.order_by(desc(RequestLog.timestamp)) \
                 .offset((page - 1) * limit) \
                 .limit(limit) \
                 .all()

    return {
        "total":   total,
        "page":    page,
        "limit":   limit,
        "pages":   (total + limit - 1) // limit,
        "logs": [
            {
                "id":           log.id,
                "timestamp":    log.timestamp.isoformat(),
                "ip_address":   log.ip_address,
                "method":       log.method,
                "path":         log.path,
                "verdict":      log.verdict,
                "threat_score": log.threat_score,
                "attack_types": log.attack_types or [],
            }
            for log in logs
        ]
    }


# ── GET /api/logs/{id} ────────────────────────────────────────────

@router.get("/logs/{log_id}")
def get_log(log_id: int, db: Session = Depends(get_db)):
    """Get full details of a single log entry."""
    log = db.query(RequestLog).filter(RequestLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log entry not found")

    return {
        "id":            log.id,
        "timestamp":     log.timestamp.isoformat(),
        "ip_address":    log.ip_address,
        "method":        log.method,
        "path":          log.path,
        "query_string":  log.query_string,
        "headers":       log.headers,
        "body":          log.body,
        "user_agent":    log.user_agent,
        "verdict":       log.verdict,
        "threat_score":  log.threat_score,
        "attack_types":  log.attack_types or [],
        "matched_rules": log.matched_rules or [],
        "is_anomaly":    log.is_anomaly,
    }


# ── GET /api/alerts ───────────────────────────────────────────────

@router.get("/alerts")
def get_alerts(
    resolved: Optional[bool] = Query(default=None),
    severity: Optional[str]  = Query(default=None),
    limit:    int = Query(default=50, le=500),
    db: Session = Depends(get_db)
):
    """Get security alerts."""
    query = db.query(Alert)

    if resolved is not None:
        query = query.filter(Alert.is_resolved == resolved)
    if severity:
        query = query.filter(Alert.severity == severity.upper())

    alerts = query.order_by(desc(Alert.timestamp)).limit(limit).all()

    return {
        "total": query.count(),
        "alerts": [
            {
                "id":          a.id,
                "timestamp":   a.timestamp.isoformat(),
                "ip_address":  a.ip_address,
                "severity":    a.severity,
                "attack_type": a.attack_type,
                "description": a.description,
                "is_resolved": a.is_resolved,
                "log_id":      a.log_id,
            }
            for a in alerts
        ]
    }


# ── GET /api/stats ────────────────────────────────────────────────

@router.get("/stats")
def get_stats(
    hours: int = Query(default=24, description="Stats window in hours"),
    db: Session = Depends(get_db)
):
    """
    Dashboard summary statistics.
    Returns counts, distributions, and top attackers.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    base  = db.query(RequestLog).filter(RequestLog.timestamp >= since)

    total       = base.count()
    blocked     = base.filter(RequestLog.verdict == "BLOCK").count()
    flagged     = base.filter(RequestLog.verdict == "FLAG").count()
    allowed     = base.filter(RequestLog.verdict == "ALLOW").count()
    anomalies   = base.filter(RequestLog.is_anomaly == True).count()
    active_bans = db.query(BannedIP).count()
    open_alerts = db.query(Alert).filter(Alert.is_resolved == False).count()

    # Top attacking IPs
    top_ips = (
        db.query(RequestLog.ip_address, func.count(RequestLog.id).label("count"))
        .filter(RequestLog.timestamp >= since, RequestLog.verdict == "BLOCK")
        .group_by(RequestLog.ip_address)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    # Attack type distribution
    attack_dist = {}
    malicious = base.filter(RequestLog.verdict.in_(["BLOCK", "FLAG"])).all()
    for log in malicious:
        for attack in (log.attack_types or []):
            attack_dist[attack] = attack_dist.get(attack, 0) + 1

    # Alerts by severity
    severity_dist = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = db.query(Alert).filter(
            Alert.timestamp >= since,
            Alert.severity == sev
        ).count()
        severity_dist[sev] = count

    return {
        "window_hours":        hours,
        "total_requests":      total,
        "blocked":             blocked,
        "flagged":             flagged,
        "allowed":             allowed,
        "anomalies_detected":  anomalies,
        "active_bans":         active_bans,
        "open_alerts":         open_alerts,
        "block_rate_pct":      round((blocked / total * 100) if total > 0 else 0, 1),
        "top_attacking_ips":   [{"ip": ip, "count": count} for ip, count in top_ips],
        "attack_distribution": attack_dist,
        "severity_distribution": severity_dist,
    }


# ── GET /api/rules ────────────────────────────────────────────────

@router.get("/rules")
def get_rules():
    """List all loaded detection rules."""
    return {"rules": rule_engine.get_loaded_rules_summary()}


# ── IP Management ─────────────────────────────────────────────────

class BanRequest(BaseModel):
    ip_address:   str
    reason:       str
    is_permanent: bool = False
    duration_hours: int = 24

class WhitelistRequest(BaseModel):
    ip_address:  str
    description: str


@router.post("/ban")
def ban_ip(req: BanRequest, db: Session = Depends(get_db)):
    """Manually ban an IP address."""
    existing = db.query(BannedIP).filter(BannedIP.ip_address == req.ip_address).first()
    if existing:
        raise HTTPException(status_code=409, detail="IP is already banned")

    expires = None if req.is_permanent else (
        datetime.utcnow() + timedelta(hours=req.duration_hours)
    )

    ban = BannedIP(
        ip_address   = req.ip_address,
        reason       = req.reason,
        expires_at   = expires,
        is_permanent = req.is_permanent,
        banned_by    = "admin",
    )
    db.add(ban)
    db.commit()
    return {"message": f"IP {req.ip_address} banned successfully", "expires_at": expires}


@router.delete("/ban/{ip_address}")
def unban_ip(ip_address: str, db: Session = Depends(get_db)):
    """Remove an IP from the ban list."""
    ban = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
    if not ban:
        raise HTTPException(status_code=404, detail="IP not found in ban list")
    db.delete(ban)
    db.commit()
    return {"message": f"IP {ip_address} unbanned successfully"}


@router.post("/whitelist")
def whitelist_ip(req: WhitelistRequest, db: Session = Depends(get_db)):
    """Add an IP to the trusted whitelist."""
    existing = db.query(WhitelistedIP).filter(WhitelistedIP.ip_address == req.ip_address).first()
    if existing:
        raise HTTPException(status_code=409, detail="IP already whitelisted")

    entry = WhitelistedIP(ip_address=req.ip_address, description=req.description)
    db.add(entry)
    db.commit()
    return {"message": f"IP {req.ip_address} added to whitelist"}


@router.get("/banned-ips")
def get_banned_ips(db: Session = Depends(get_db)):
    """List all currently banned IPs."""
    bans = db.query(BannedIP).all()
    return {"bans": [
        {
            "ip_address":   b.ip_address,
            "reason":       b.reason,
            "banned_at":    b.banned_at.isoformat(),
            "expires_at":   b.expires_at.isoformat() if b.expires_at else None,
            "is_permanent": b.is_permanent,
            "banned_by":    b.banned_by,
        }
        for b in bans
    ]}
