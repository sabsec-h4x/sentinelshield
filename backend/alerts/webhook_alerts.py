# ─────────────────────────────────────────────────────────────────
#  alerts/webhook_alerts.py — Real-Time Alert Notifications
#
#  WHAT IT DOES:
#  Sends instant notifications to Slack, Discord, or Email
#  whenever SentinelShield detects a CRITICAL or HIGH severity attack.
#
#  HOW TO CONFIGURE:
#  Create a .env file in the backend folder with:
#
#    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/xxx/xxx
#    DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/xxx
#    EMAIL_HOST=smtp.gmail.com
#    EMAIL_PORT=587
#    EMAIL_USER=your@gmail.com
#    EMAIL_PASS=your_app_password
#    EMAIL_TO=security@yourcompany.com
#
#  HOW TO GET WEBHOOK URLs:
#  Slack:   https://api.slack.com/messaging/webhooks
#  Discord: Server Settings → Integrations → Webhooks → New Webhook
# ─────────────────────────────────────────────────────────────────

import os
import sys
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from dotenv import load_dotenv
load_dotenv()


@dataclass
class AlertPayload:
    """Data for an alert notification."""
    severity:    str    # CRITICAL / HIGH / MEDIUM / LOW
    verdict:     str    # BLOCK / FLAG
    ip_address:  str
    attack_type: str
    threat_score:float
    path:        str
    country:     str = "Unknown"
    is_tor:      bool = False
    is_anomaly:  bool = False
    timestamp:   str  = ""
    request_id:  int  = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')


class AlertManager:
    """
    Manages sending alerts to multiple channels.

    Channels:
    - Slack  (webhook)
    - Discord (webhook)
    - Email  (SMTP)

    Usage:
        manager = AlertManager()

        # Called automatically after each BLOCK/FLAG decision
        manager.send_alert(AlertPayload(
            severity    = "CRITICAL",
            verdict     = "BLOCK",
            ip_address  = "185.220.101.50",
            attack_type = "SQL Injection",
            threat_score= 100.0,
            path        = "/login",
            country     = "Germany",
            is_tor      = True,
        ))
    """

    def __init__(self):
        self.slack_url   = os.getenv('SLACK_WEBHOOK_URL',   '')
        self.discord_url = os.getenv('DISCORD_WEBHOOK_URL', '')
        self.email_host  = os.getenv('EMAIL_HOST',  'smtp.gmail.com')
        self.email_port  = int(os.getenv('EMAIL_PORT', '587'))
        self.email_user  = os.getenv('EMAIL_USER',  '')
        self.email_pass  = os.getenv('EMAIL_PASS',  '')
        self.email_to    = os.getenv('EMAIL_TO',    '')

        # Only send alerts for these severities
        self.alert_severities = {'CRITICAL', 'HIGH'}

        channels = []
        if self.slack_url:   channels.append('Slack')
        if self.discord_url: channels.append('Discord')
        if self.email_user:  channels.append('Email')

        if channels:
            print(f"✅ Alert Manager ready: {', '.join(channels)}")
        else:
            print("⚠️  Alert Manager: No webhooks configured (add to .env file)")

    def send_alert(self, alert: AlertPayload) -> bool:
        """
        Send alert to all configured channels.
        Only sends for CRITICAL and HIGH severity.
        Returns True if at least one channel succeeded.
        """
        if alert.severity not in self.alert_severities:
            return False  # Don't spam for LOW/MEDIUM alerts

        sent = False
        if self.slack_url:
            sent = self._send_slack(alert)  or sent
        if self.discord_url:
            sent = self._send_discord(alert) or sent
        if self.email_user and self.email_to:
            sent = self._send_email(alert)   or sent

        return sent

    def _send_slack(self, alert: AlertPayload) -> bool:
        """Send formatted Slack message."""
        if not HTTPX_AVAILABLE:
            return False

        sev_emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '⚠️', 'LOW': '📋'}
        emoji = sev_emoji.get(alert.severity, '🔔')

        # Slack Block Kit message format
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} SentinelShield {alert.severity} Alert",
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Verdict:*\n`{alert.verdict}`"},
                        {"type": "mrkdwn", "text": f"*Attack Type:*\n{alert.attack_type}"},
                        {"type": "mrkdwn", "text": f"*IP Address:*\n`{alert.ip_address}`"},
                        {"type": "mrkdwn", "text": f"*Threat Score:*\n{alert.threat_score}/100"},
                        {"type": "mrkdwn", "text": f"*Country:*\n{alert.country}"},
                        {"type": "mrkdwn", "text": f"*Path:*\n`{alert.path}`"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{'🧅 Tor Exit Node  ' if alert.is_tor else ''}"
                            f"{'🤖 ML Anomaly  ' if alert.is_anomaly else ''}"
                            f"\n_Time: {alert.timestamp}_"
                        )
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View Dashboard"},
                            "url": "http://localhost:3000",
                            "style": "danger",
                        }
                    ]
                }
            ]
        }

        try:
            resp = httpx.post(self.slack_url, json=payload, timeout=5)
            if resp.status_code == 200:
                print(f"✅ Slack alert sent for {alert.ip_address}")
                return True
            else:
                print(f"⚠️  Slack error: {resp.status_code}")
                return False
        except Exception as e:
            print(f"❌ Slack failed: {e}")
            return False

    def _send_discord(self, alert: AlertPayload) -> bool:
        """Send formatted Discord embed message."""
        if not HTTPX_AVAILABLE:
            return False

        sev_color = {'CRITICAL': 0xFF0033, 'HIGH': 0xFF4D4D, 'MEDIUM': 0xFF9900, 'LOW': 0x5577FF}
        color = sev_color.get(alert.severity, 0x5577FF)

        payload = {
            "username": "SentinelShield",
            "avatar_url": "https://i.imgur.com/shield.png",
            "embeds": [{
                "title": f"🛡️ {alert.severity} Security Alert",
                "color": color,
                "fields": [
                    {"name": "Verdict",      "value": f"`{alert.verdict}`",          "inline": True},
                    {"name": "Attack Type",  "value": alert.attack_type,             "inline": True},
                    {"name": "IP Address",   "value": f"`{alert.ip_address}`",       "inline": True},
                    {"name": "Threat Score", "value": f"{alert.threat_score}/100",   "inline": True},
                    {"name": "Country",      "value": alert.country,                 "inline": True},
                    {"name": "Path",         "value": f"`{alert.path}`",             "inline": True},
                ],
                "footer": {
                    "text": f"SentinelShield v2.0 • {alert.timestamp}"
                },
                "description": (
                    ("🧅 **Tor Exit Node Detected**\n" if alert.is_tor else "") +
                    ("🤖 **ML Anomaly Detected**\n" if alert.is_anomaly else "")
                ) or "Standard rule-based detection",
            }]
        }

        try:
            resp = httpx.post(self.discord_url, json=payload, timeout=5)
            if resp.status_code in (200, 204):
                print(f"✅ Discord alert sent for {alert.ip_address}")
                return True
            else:
                print(f"⚠️  Discord error: {resp.status_code}")
                return False
        except Exception as e:
            print(f"❌ Discord failed: {e}")
            return False

    def _send_email(self, alert: AlertPayload) -> bool:
        """Send HTML email alert."""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[SentinelShield] {alert.severity} Alert — {alert.attack_type} from {alert.ip_address}"
            msg['From']    = self.email_user
            msg['To']      = self.email_to

            sev_color = {'CRITICAL':'#ff0033','HIGH':'#ff4d4d','MEDIUM':'#ff9900','LOW':'#5577ff'}
            color = sev_color.get(alert.severity, '#5577ff')

            html = f"""
            <html><body style="font-family: Arial, sans-serif; background:#f5f5f5; padding:20px;">
            <div style="max-width:600px; margin:0 auto; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 10px rgba(0,0,0,0.1);">
                <div style="background:#050510; padding:20px; text-align:center;">
                    <h1 style="color:#fff; margin:0; font-size:24px;">🛡️ SentinelShield</h1>
                    <p style="color:#888; margin:5px 0 0;">Security Alert Notification</p>
                </div>
                <div style="padding:24px;">
                    <div style="background:{color}15; border:1px solid {color}44; border-radius:6px; padding:16px; margin-bottom:20px; text-align:center;">
                        <span style="font-size:28px; font-weight:bold; color:{color};">{alert.severity}</span>
                        <br><span style="color:#666; font-size:14px;">{alert.verdict} — Threat Score: {alert.threat_score}/100</span>
                    </div>
                    <table style="width:100%; border-collapse:collapse;">
                        <tr style="background:#f9f9f9;"><td style="padding:10px; font-weight:bold; color:#333; width:40%;">IP Address</td><td style="padding:10px; color:#cc2222; font-family:monospace;">{alert.ip_address}</td></tr>
                        <tr><td style="padding:10px; font-weight:bold; color:#333;">Attack Type</td><td style="padding:10px; color:#555;">{alert.attack_type}</td></tr>
                        <tr style="background:#f9f9f9;"><td style="padding:10px; font-weight:bold; color:#333;">Country</td><td style="padding:10px; color:#555;">{alert.country}</td></tr>
                        <tr><td style="padding:10px; font-weight:bold; color:#333;">Path</td><td style="padding:10px; font-family:monospace; color:#555;">{alert.path}</td></tr>
                        <tr style="background:#f9f9f9;"><td style="padding:10px; font-weight:bold; color:#333;">Tor Node</td><td style="padding:10px; color:#555;">{'Yes 🧅' if alert.is_tor else 'No'}</td></tr>
                        <tr><td style="padding:10px; font-weight:bold; color:#333;">ML Anomaly</td><td style="padding:10px; color:#555;">{'Yes 🤖' if alert.is_anomaly else 'No'}</td></tr>
                        <tr style="background:#f9f9f9;"><td style="padding:10px; font-weight:bold; color:#333;">Timestamp</td><td style="padding:10px; color:#555;">{alert.timestamp}</td></tr>
                    </table>
                    <div style="margin-top:20px; text-align:center;">
                        <a href="http://localhost:3000" style="background:#0044cc; color:#fff; padding:12px 24px; border-radius:5px; text-decoration:none; font-weight:bold;">View Dashboard</a>
                    </div>
                </div>
                <div style="background:#f5f5f5; padding:12px; text-align:center; font-size:12px; color:#999;">
                    SentinelShield v2.0 — Advanced Intrusion Detection System
                </div>
            </div>
            </body></html>
            """

            msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(self.email_host, self.email_port) as server:
                server.starttls()
                server.login(self.email_user, self.email_pass)
                server.send_message(msg)

            print(f"✅ Email alert sent for {alert.ip_address}")
            return True

        except Exception as e:
            print(f"❌ Email failed: {e}")
            return False


# ── Test Function ─────────────────────────────────────────────────
def test_alerts():
    """Send a test alert to verify configuration."""
    manager = AlertManager()
    test_payload = AlertPayload(
        severity    = "CRITICAL",
        verdict     = "BLOCK",
        ip_address  = "185.220.101.50",
        attack_type = "SQL Injection",
        threat_score= 100.0,
        path        = "/login?id=1' UNION SELECT--",
        country     = "Germany",
        is_tor      = True,
        is_anomaly  = True,
    )
    result = manager.send_alert(test_payload)
    print(f"\n{'✅ Test alert sent!' if result else '⚠️  No channels configured — add webhook URLs to .env file'}")


# ── Singleton ─────────────────────────────────────────────────────
alert_manager = AlertManager()


if __name__ == "__main__":
    test_alerts()
