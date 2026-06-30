# ─────────────────────────────────────────────────────────────────
#  core/decision_engine.py — ALLOW / FLAG / BLOCK Decision Logic
#
#  This is the "brain" of SentinelShield. It takes the results from:
#    - Rule Engine (signature matches + score)
#    - Rate Limiter (is this IP sending too many requests?)
#    - ML Detector  (is this request anomalous/zero-day?)
#    - Banned IP list (is this IP already banned?)
#    - Whitelist    (is this IP trusted?)
#
#  And produces a final verdict:
#    ALLOW   → Clean request, let it through
#    FLAG    → Suspicious, log it and alert but allow
#    BLOCK   → Malicious, reject it immediately
#
#  SEVERITY LEVELS:
#    Score 0–29:   ALLOW  (clean)
#    Score 30–59:  FLAG   (suspicious — needs review)
#    Score 60–100: BLOCK  (malicious — reject)
# ─────────────────────────────────────────────────────────────────

import sys
import os
from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config import SCORE_FLAG_THRESHOLD, SCORE_BLOCK_THRESHOLD
from core.rule_engine import DetectionResult


# ── Data Structures ───────────────────────────────────────────────

@dataclass
class DecisionResult:
    """
    The final decision output for one request.
    Contains everything needed to log, alert, and respond.
    """
    # Core verdict
    verdict:      str    # "ALLOW", "FLAG", or "BLOCK"
    threat_score: float  # 0.0 to 100.0

    # Why was this decision made?
    reasons:      List[str] = field(default_factory=list)

    # Alert details (if FLAG or BLOCK)
    should_alert: bool  = False
    severity:     str   = "LOW"   # LOW / MEDIUM / HIGH / CRITICAL
    alert_message:str   = ""

    # Response to send back to the client
    http_status:  int   = 200     # 200=OK, 403=Forbidden
    response_message: str = ""

    # Extra flags
    is_banned_ip:    bool = False
    is_whitelisted:  bool = False
    is_rate_limited: bool = False
    is_anomaly:      bool = False
    attack_types:    List[str] = field(default_factory=list)


# ── Decision Engine Class ─────────────────────────────────────────

class DecisionEngine:
    """
    Takes all detection signals and produces a final ALLOW/FLAG/BLOCK decision.
    """

    def decide(
        self,
        detection_result: DetectionResult,
        ip_address: str,
        is_banned: bool = False,
        is_whitelisted: bool = False,
        is_rate_limited: bool = False,
        is_anomaly: bool = False,
        anomaly_score: float = 0.0,
        is_tor: bool = False,
    ) -> DecisionResult:
        """
        Main decision method. Returns a DecisionResult.

        PRIORITY ORDER (highest priority first):
        1. Whitelisted IP  → always ALLOW, skip all other checks
        2. Banned IP       → always BLOCK immediately
        3. Rate limited    → BLOCK (brute-force / DDoS protection)
        4. Rule matches    → BLOCK or FLAG based on score
        5. ML anomaly      → FLAG if no rule matched but looks weird
        6. Clean           → ALLOW
        """

        # ── Priority 1: Whitelisted ───────────────────────────────
        if is_whitelisted:
            return DecisionResult(
                verdict        = "ALLOW",
                threat_score   = 0.0,
                reasons        = ["IP is on the whitelist — all checks bypassed"],
                is_whitelisted = True,
                http_status    = 200,
                response_message = "Request allowed (trusted IP)",
            )

        # ── Priority 2: Banned IP ─────────────────────────────────
        if is_banned:
            return DecisionResult(
                verdict       = "BLOCK",
                threat_score  = 100.0,
                reasons       = ["IP address is on the ban list"],
                should_alert  = True,
                severity      = "HIGH",
                alert_message = f"Blocked request from banned IP: {ip_address}",
                is_banned_ip  = True,
                http_status   = 403,
                response_message = "Access denied: Your IP has been blocked.",
            )

        # ── Priority 3: Rate Limited ──────────────────────────────
        if is_rate_limited:
            return DecisionResult(
                verdict          = "BLOCK",
                threat_score     = 80.0,
                reasons          = ["IP exceeded request rate limit — possible brute-force or DDoS"],
                should_alert     = True,
                severity         = "HIGH",
                alert_message    = f"Rate limit exceeded by {ip_address}",
                is_rate_limited  = True,
                http_status      = 429,
                response_message = "Too many requests. Please slow down.",
            )

        # ── Build threat score from rule matches ──────────────────
        threat_score = detection_result.total_score
        reasons      = []
        attack_types = detection_result.categories.copy()

        # Add ML anomaly score on top (if active)
        if is_anomaly and anomaly_score > 0:
            threat_score += anomaly_score * 30  # anomaly_score is 0–1, scale to 0–30
            reasons.append(f"ML anomaly detector flagged this request (score: {anomaly_score:.2f})")

        # Collect reasons from rule matches
        for match in detection_result.matches:
            reasons.append(f"{match.category} — {match.rule_name} (score +{match.final_score:.1f})")

        # Cap at 100
        threat_score = min(100.0, threat_score)

        # ── Priority 4: Make BLOCK / FLAG / ALLOW decision ────────
        if threat_score >= SCORE_BLOCK_THRESHOLD or len(detection_result.matches) >= 2:
            # Multiple matches or high score = definitive attack
            severity = self._calculate_severity(threat_score, detection_result)
            return DecisionResult(
                verdict       = "BLOCK",
                threat_score  = threat_score,
                reasons       = reasons,
                should_alert  = True,
                severity      = severity,
                alert_message = f"Attack detected from {ip_address}: {', '.join(attack_types)}",
                http_status   = 403,
                response_message = "Request blocked: Malicious content detected.",
                attack_types  = attack_types,
                is_anomaly    = is_anomaly,
            )

        elif threat_score >= SCORE_FLAG_THRESHOLD or detection_result.is_malicious:
            # Single match or moderate score = suspicious
            return DecisionResult(
                verdict       = "FLAG",
                threat_score  = threat_score,
                reasons       = reasons,
                should_alert  = True,
                severity      = "MEDIUM",
                alert_message = f"Suspicious request from {ip_address}: {', '.join(attack_types) if attack_types else 'anomaly'}",
                http_status   = 200,   # Allow through but flag for review
                response_message = "Request processed (flagged for review).",
                attack_types  = attack_types,
                is_anomaly    = is_anomaly,
            )

        elif is_anomaly:
            # ML detected something odd but no rules matched
            return DecisionResult(
                verdict       = "FLAG",
                threat_score  = max(threat_score, 25.0),
                reasons       = reasons or ["ML anomaly detection triggered — no matching signature"],
                should_alert  = True,
                severity      = "LOW",
                alert_message = f"Anomalous request from {ip_address} — possible zero-day",
                http_status   = 200,
                response_message = "Request processed (anomaly flagged).",
                is_anomaly    = True,
            )

        # ── Priority 5: Clean request ─────────────────────────────
        return DecisionResult(
            verdict          = "ALLOW",
            threat_score     = 0.0,
            reasons          = ["No threats detected"],
            should_alert     = False,
            http_status      = 200,
            response_message = "Request allowed.",
        )

    def _calculate_severity(self, score: float, result: DetectionResult) -> str:
        """
        Determines alert severity based on threat score and attack types.
        
        CRITICAL: Score >= 85 or command injection or reverse shell
        HIGH:     Score >= 65 or SQL injection
        MEDIUM:   Score >= 40
        LOW:      Everything else
        """
        # Command injection / reverse shell are always critical
        critical_categories = ["Command Injection"]
        if any(c in result.categories for c in critical_categories):
            return "CRITICAL"

        if score >= 85:
            return "CRITICAL"
        elif score >= 65:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"


# ── Singleton ─────────────────────────────────────────────────────
decision_engine = DecisionEngine()
