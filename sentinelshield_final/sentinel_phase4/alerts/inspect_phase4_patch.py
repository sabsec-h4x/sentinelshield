# ─────────────────────────────────────────────────────────────────
#  api/inspect_phase4.py — Phase 4 upgrade to inspect.py
#
#  COPY THIS CODE into your existing api/inspect.py
#  Replace the section "Step 11: Create Alert" with this version
#  to enable Slack/Discord/Email notifications
# ─────────────────────────────────────────────────────────────────

# Add these imports to top of api/inspect.py:
#
# from alerts.webhook_alerts import alert_manager, AlertPayload
#
# Then replace the "Create Alert" section with:

ALERT_INTEGRATION_CODE = '''
    # ── Step 11: Create Alert + Send Webhook Notification ────────
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

        # Send real-time webhook notification (Slack/Discord/Email)
        try:
            from alerts.webhook_alerts import alert_manager, AlertPayload
            alert_manager.send_alert(AlertPayload(
                severity     = decision.severity,
                verdict      = decision.verdict,
                ip_address   = payload.ip,
                attack_type  = ", ".join(decision.attack_types) if decision.attack_types else "Anomaly",
                threat_score = decision.threat_score,
                path         = payload.path + ("?" + payload.query if payload.query else ""),
                country      = geo_data.country_name if geo_data else "Unknown",
                is_tor       = geo_data.is_tor if geo_data else False,
                is_anomaly   = is_anomaly,
                request_id   = log_entry.id,
            ))
        except Exception as e:
            print(f"Alert webhook error: {e}")
'''

print("Integration code ready!")
print("Add the imports and replace Step 11 in api/inspect.py")
print(ALERT_INTEGRATION_CODE)
