# ─────────────────────────────────────────────────────────────────
#  api/inspect.py — UPDATED for Phase 2
#
#  NEW in Phase 2:
#  ✅ ML Zero-Day Detection (Isolation Forest)
#  ✅ Redis Rate Limiting
#  ✅ GeoIP + IP Reputation
#  ✅ Enhanced threat scoring
#  ✅ Richer response with geo data
# ─────────────────────────────────────────────────────────────────

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from models.database import get_db, RequestLog, Alert, BannedIP, WhitelistedIP
from core.parser import RequestParser
from core.rule_engine import rule_engine
from core.decision_engine import decision_engine
from core.rate_limiter import rate_limiter
from core.geo_reputation import geo_checker
from ml.anomaly_detector import anomaly_detector
from config import AUTO_BAN_THRESHOLD, AUTO_BAN_DURATION_SEC

router = APIRouter(prefix="/api", tags=["Inspection"])


# ── Schemas ───────────────────────────────────────────────────────

class InspectRequest(BaseModel):
    ip:      str  = Field(default="127.0.0.1")
    method:  str  = Field(default="GET")
    path:    str  = Field(default="/")
    query:   str  = Field(default="")
    headers: Dict[str, str] = Field(default={})
    body:    Optional[str]  = Field(default=None)

    class Config:
        json_schema_extra = {
            "example": {
                "ip": "192.168.1.100",
                "method": "GET",
                "path": "/search",
                "query": "q=1' UNION SELECT username,password FROM users--",
                "headers": {"User-Agent": "Mozilla/5.0"},
                "body": None
            }
        }


class InspectResponse(BaseModel):
    request_id:    int
    verdict:       str
    threat_score:  float
    attack_types:  list
    matches:       list
    reasons:       list
    severity:      str
    blocked:       bool
    timestamp:     str

    # Phase 2 additions
    rate_limited:  bool  = False
    is_anomaly:    bool  = False
    anomaly_score: float = 0.0
    geo: dict = {}


# ── POST /api/inspect (Phase 2) ───────────────────────────────────

@router.post("/inspect", response_model=InspectResponse)
async def inspect_request(
    payload: InspectRequest,
    db: Session = Depends(get_db),
):
    """
    Inspect an HTTP request — now with ML, Rate Limiting & GeoIP.
    """

    # ── Step 1: Whitelist Check ───────────────────────────────────
    whitelist_entry = db.query(WhitelistedIP).filter(
        WhitelistedIP.ip_address == payload.ip
    ).first()
    is_whitelisted = whitelist_entry is not None

    # ── Step 2: Ban Check ─────────────────────────────────────────
    ban_entry = db.query(BannedIP).filter(
        BannedIP.ip_address == payload.ip
    ).first()
    is_banned = False
    if ban_entry:
        if ban_entry.expires_at and ban_entry.expires_at < datetime.utcnow():
            db.delete(ban_entry)
            db.commit()
        else:
            is_banned = True

    # ── Step 3: Rate Limit Check (NEW Phase 2) ────────────────────
    is_rate_limited = False
    if not is_whitelisted and not is_banned:
        rate_result     = rate_limiter.check(payload.ip)
        is_rate_limited = rate_result.is_limited

    # ── Step 4: GeoIP + Reputation (NEW Phase 2) ──────────────────
    geo_data = None
    if not is_whitelisted:
        try:
            geo_data = geo_checker.check(payload.ip)
        except Exception:
            geo_data = None

    # ── Step 5: Parse Request ─────────────────────────────────────
    parser = RequestParser()
    parsed = parser.parse({
        "ip":      payload.ip,
        "method":  payload.method,
        "path":    payload.path,
        "query":   payload.query,
        "headers": payload.headers,
        "body":    payload.body,
    })

    # ── Step 6: Rule Engine ───────────────────────────────────────
    detection_result = rule_engine.analyze(parsed)

    # ── Step 7: ML Anomaly Detection (NEW Phase 2) ────────────────
    is_anomaly    = False
    anomaly_score = 0.0
    if not is_whitelisted and not is_banned and not is_rate_limited:
        try:
            anomaly_score, is_anomaly = anomaly_detector.predict({
                "ip":     payload.ip,
                "method": payload.method,
                "path":   payload.path,
                "query":  payload.query,
                "body":   payload.body,
            })
        except Exception as e:
            print(f"ML prediction error: {e}")

    # ── Step 8: Boost score for bad reputation IPs ────────────────
    geo_reputation_boost = 0.0
    if geo_data and not is_whitelisted:
        if geo_data.is_tor:
            geo_reputation_boost += 20.0
        if geo_data.is_datacenter and detection_result.is_malicious:
            geo_reputation_boost += 10.0
        if geo_data.reputation_score > 50:
            geo_reputation_boost += geo_data.reputation_score * 0.2

    # ── Step 9: Decision Engine ───────────────────────────────────
    decision = decision_engine.decide(
        detection_result  = detection_result,
        ip_address        = payload.ip,
        is_banned         = is_banned,
        is_whitelisted    = is_whitelisted,
        is_rate_limited   = is_rate_limited,
        is_anomaly        = is_anomaly,
        anomaly_score     = anomaly_score,
    )

    # Apply geo reputation boost to score
    if geo_reputation_boost > 0 and decision.verdict != "ALLOW":
        decision.threat_score = min(100.0, decision.threat_score + geo_reputation_boost)
        if geo_data and geo_data.is_tor:
            decision.reasons.append("Tor exit node detected — reputation boost applied")

    # ── Step 10: Save to Database ─────────────────────────────────
    log_entry = RequestLog(
        ip_address    = payload.ip,
        method        = payload.method,
        path          = payload.path,
        query_string  = payload.query,
        headers       = payload.headers,
        body          = payload.body,
        user_agent    = payload.headers.get("User-Agent", ""),
        verdict       = decision.verdict,
        threat_score  = decision.threat_score,
        attack_types  = decision.attack_types,
        matched_rules = [
            {
                "rule_id":      m.rule_id,
                "rule_name":    m.rule_name,
                "category":     m.category,
                "severity":     m.severity,
                "matched_text": m.matched_value,
                "score":        m.final_score,
            }
            for m in detection_result.matches
        ],
        is_anomaly    = is_anomaly,
        country_code  = geo_data.country_code if geo_data else None,
        asn           = geo_data.asn          if geo_data else None,
        is_tor        = geo_data.is_tor        if geo_data else False,
        is_vpn        = geo_data.is_vpn        if geo_data else False,
    )
    db.add(log_entry)
    db.flush()

    # ── Step 11: Create Alert ─────────────────────────────────────
    if decision.should_alert:
        alert = Alert(
            log_id      = log_entry.id,
            ip_address  = payload.ip,
            severity    = decision.severity,
            attack_type = ", ".join(decision.attack_types) if decision.attack_types else (
                "Zero-Day Anomaly" if is_anomaly else "Rate Limit Abuse"
            ),
            description = decision.alert_message,
        )
        db.add(alert)

    # ── Step 12: Auto-Ban ─────────────────────────────────────────
    if decision.verdict == "BLOCK" and not is_banned and not is_whitelisted:
        block_count = db.query(RequestLog).filter(
            RequestLog.ip_address == payload.ip,
            RequestLog.verdict    == "BLOCK"
        ).count()

        if block_count >= AUTO_BAN_THRESHOLD - 1:
            existing_ban = db.query(BannedIP).filter(
                BannedIP.ip_address == payload.ip
            ).first()
            if not existing_ban:
                ban = BannedIP(
                    ip_address   = payload.ip,
                    reason       = f"Auto-banned: {AUTO_BAN_THRESHOLD} malicious requests detected",
                    expires_at   = datetime.utcnow() + timedelta(seconds=AUTO_BAN_DURATION_SEC),
                    is_permanent = False,
                    banned_by    = "auto",
                )
                db.add(ban)

    db.commit()
    db.refresh(log_entry)

    # ── Step 13: Build Geo Response ───────────────────────────────
    geo_response = {}
    if geo_data:
        geo_response = {
            "country_code":  geo_data.country_code,
            "country_name":  geo_data.country_name,
            "city":          geo_data.city,
            "isp":           geo_data.isp,
            "is_tor":        geo_data.is_tor,
            "is_vpn":        geo_data.is_vpn,
            "is_datacenter": geo_data.is_datacenter,
            "reputation_score": geo_data.reputation_score,
            "risk_flags":    geo_data.risk_flags,
        }

    # ── Step 14: Return Response ──────────────────────────────────
    return InspectResponse(
        request_id    = log_entry.id,
        verdict       = decision.verdict,
        threat_score  = round(decision.threat_score, 1),
        attack_types  = decision.attack_types,
        matches       = [
            {
                "rule_id":   m.rule_id,
                "rule_name": m.rule_name,
                "category":  m.category,
                "severity":  m.severity,
                "matched":   m.matched_value,
                "score":     round(m.final_score, 1),
            }
            for m in detection_result.matches
        ],
        reasons       = decision.reasons,
        severity      = decision.severity,
        blocked       = decision.verdict == "BLOCK",
        timestamp     = log_entry.timestamp.isoformat(),
        rate_limited  = is_rate_limited,
        is_anomaly    = is_anomaly,
        anomaly_score = anomaly_score,
        geo           = geo_response,
    )


# ── GET /api/rate-stats/{ip} ──────────────────────────────────────

@router.get("/rate-stats/{ip_address}", tags=["Phase 2"])
def get_rate_stats(ip_address: str):
    """Check current rate limit status for an IP."""
    return rate_limiter.get_ip_stats(ip_address)


# ── POST /api/ml/retrain ──────────────────────────────────────────

@router.post("/ml/retrain", tags=["Phase 2"])
def retrain_ml_model():
    """Retrain the ML anomaly detection model."""
    try:
        anomaly_detector.train()
        return {"message": "ML model retrained successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /api/ml/status ────────────────────────────────────────────

@router.get("/ml/status", tags=["Phase 2"])
def ml_status():
    """Check ML model status."""
    return {
        "ml_available": anomaly_detector.trained,
        "model_file_exists": os.path.exists(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml", "model.pkl")
        ),
    }
