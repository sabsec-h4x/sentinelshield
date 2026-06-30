# ─────────────────────────────────────────────────────────────────
#  reports/report_generator.py — Automated PDF Report Generator
#
#  WHAT IT DOES:
#  Generates a professional security report PDF with:
#  - Executive summary (total attacks, block rate, top threats)
#  - Attack type breakdown table
#  - Top attacking IPs table
#  - Severity distribution
#  - Timeline of attacks
#  - Recommendations
#
#  HOW TO RUN:
#    python reports/report_generator.py
#    → Creates: sentinelshield_report_2026-03-15.pdf
#
#  INSTALL DEPENDENCY:
#    pip install reportlab
# ─────────────────────────────────────────────────────────────────

import os
import sys
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table,
        TableStyle, HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠️  reportlab not installed. Run: pip install reportlab")

from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from models.database import SessionLocal, RequestLog, Alert, BannedIP


# ── Color Palette ─────────────────────────────────────────────────
DARK_BG    = colors.HexColor('#050510')
ACCENT     = colors.HexColor('#0044cc')
BLOCK_RED  = colors.HexColor('#cc2222')
FLAG_ORG   = colors.HexColor('#cc7700')
ALLOW_GRN  = colors.HexColor('#006633')
CRIT_RED   = colors.HexColor('#ff0033')
LIGHT_GREY = colors.HexColor('#f5f5f5')
MID_GREY   = colors.HexColor('#cccccc')
DARK_GREY  = colors.HexColor('#333333')
WHITE      = colors.white
BLACK      = colors.black


def generate_report(hours: int = 24, output_path: str = None) -> str:
    """
    Generate a PDF security report for the given time window.

    Args:
        hours:       How many hours of data to include (default: 24)
        output_path: Where to save the PDF (default: current directory)

    Returns:
        Path to the generated PDF file
    """
    if not REPORTLAB_AVAILABLE:
        print("❌ Cannot generate PDF — reportlab not installed")
        print("   Run: pip install reportlab")
        return None

    # ── Fetch Data from Database ──────────────────────────────────
    db: Session = SessionLocal()
    since = datetime.utcnow() - timedelta(hours=hours)

    try:
        # Basic counts
        total    = db.query(RequestLog).filter(RequestLog.timestamp >= since).count()
        blocked  = db.query(RequestLog).filter(RequestLog.timestamp >= since, RequestLog.verdict == 'BLOCK').count()
        flagged  = db.query(RequestLog).filter(RequestLog.timestamp >= since, RequestLog.verdict == 'FLAG').count()
        allowed  = db.query(RequestLog).filter(RequestLog.timestamp >= since, RequestLog.verdict == 'ALLOW').count()
        anomalies= db.query(RequestLog).filter(RequestLog.timestamp >= since, RequestLog.is_anomaly == True).count()
        bans     = db.query(BannedIP).count()

        # Top attacking IPs
        top_ips = (
            db.query(RequestLog.ip_address, func.count(RequestLog.id).label('count'))
            .filter(RequestLog.timestamp >= since, RequestLog.verdict == 'BLOCK')
            .group_by(RequestLog.ip_address)
            .order_by(desc('count'))
            .limit(10)
            .all()
        )

        # Attack distribution
        malicious_logs = (
            db.query(RequestLog)
            .filter(RequestLog.timestamp >= since, RequestLog.verdict.in_(['BLOCK', 'FLAG']))
            .all()
        )
        attack_dist = {}
        for log in malicious_logs:
            for attack in (log.attack_types or []):
                attack_dist[attack] = attack_dist.get(attack, 0) + 1

        # Recent alerts
        recent_alerts = (
            db.query(Alert)
            .filter(Alert.timestamp >= since)
            .order_by(desc(Alert.timestamp))
            .limit(20)
            .all()
        )

        # Severity distribution
        sev_dist = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            sev_dist[sev] = db.query(Alert).filter(
                Alert.timestamp >= since, Alert.severity == sev
            ).count()

        # Recent malicious logs for timeline
        recent_malicious = (
            db.query(RequestLog)
            .filter(RequestLog.timestamp >= since, RequestLog.verdict.in_(['BLOCK', 'FLAG']))
            .order_by(desc(RequestLog.timestamp))
            .limit(15)
            .all()
        )

    finally:
        db.close()

    # ── Build PDF ─────────────────────────────────────────────────
    if not output_path:
        date_str    = datetime.now().strftime('%Y-%m-%d_%H-%M')
        output_path = f"sentinelshield_report_{date_str}.pdf"

    doc = SimpleDocTemplate(
        output_path,
        pagesize      = A4,
        rightMargin   = 2*cm,
        leftMargin    = 2*cm,
        topMargin     = 2*cm,
        bottomMargin  = 2*cm,
    )

    # Styles
    styles = getSampleStyleSheet()

    style_title = ParagraphStyle('Title',
        fontSize=28, fontName='Helvetica-Bold',
        textColor=DARK_GREY, alignment=TA_LEFT, spaceAfter=4,
    )
    style_subtitle = ParagraphStyle('Subtitle',
        fontSize=12, fontName='Helvetica',
        textColor=colors.HexColor('#666666'), alignment=TA_LEFT, spaceAfter=20,
    )
    style_section = ParagraphStyle('Section',
        fontSize=14, fontName='Helvetica-Bold',
        textColor=ACCENT, spaceBefore=16, spaceAfter=8,
        borderPad=4,
    )
    style_body = ParagraphStyle('Body',
        fontSize=10, fontName='Helvetica',
        textColor=DARK_GREY, spaceAfter=6, leading=16,
    )
    style_small = ParagraphStyle('Small',
        fontSize=8, fontName='Helvetica',
        textColor=colors.HexColor('#888888'),
    )
    style_center = ParagraphStyle('Center',
        fontSize=10, fontName='Helvetica',
        textColor=DARK_GREY, alignment=TA_CENTER,
    )

    # ── Build Content ─────────────────────────────────────────────
    story = []

    # Header
    story.append(Paragraph("🛡️ SentinelShield", style_title))
    story.append(Paragraph("Security Incident Report", style_subtitle))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=8))

    # Report metadata
    meta_data = [
        ['Report Generated:', datetime.now().strftime('%B %d, %Y at %H:%M UTC')],
        ['Analysis Window:', f'Last {hours} hours ({since.strftime("%Y-%m-%d %H:%M")} — {datetime.utcnow().strftime("%Y-%m-%d %H:%M")})'],
        ['System Version:', 'SentinelShield v2.0 (Phase 1+2+3+4)'],
        ['Detection Engine:', '31 Signatures + ML Isolation Forest + GeoIP'],
    ]
    meta_table = Table(meta_data, colWidths=[5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME',  (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',  (1,0), (1,-1), 'Helvetica'),
        ('FONTSIZE',  (0,0), (-1,-1), 9),
        ('TEXTCOLOR', (0,0), (0,-1), DARK_GREY),
        ('TEXTCOLOR', (1,0), (1,-1), colors.HexColor('#555555')),
        ('TOPPADDING',(0,0), (-1,-1), 3),
        ('BOTTOMPADDING',(0,0), (-1,-1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # ── Executive Summary ─────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", style_section))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY, spaceAfter=10))

    block_rate = round(blocked / total * 100, 1) if total > 0 else 0

    summary_data = [
        ['Metric', 'Value', 'Status'],
        ['Total Requests Analyzed', str(total), ''],
        ['Requests Blocked', str(blocked), f'{block_rate}% block rate'],
        ['Requests Flagged', str(flagged), 'Under review'],
        ['Requests Allowed', str(allowed), 'Clean traffic'],
        ['Zero-Day Anomalies (ML)', str(anomalies), 'ML detected'],
        ['IPs Currently Banned', str(bans), 'Active bans'],
        ['Critical Alerts', str(sev_dist.get('CRITICAL', 0)), ''],
    ]

    summary_table = Table(summary_data, colWidths=[8*cm, 4*cm, 5*cm])
    summary_table.setStyle(TableStyle([
        # Header row
        ('BACKGROUND',   (0,0), (-1,0), ACCENT),
        ('TEXTCOLOR',    (0,0), (-1,0), WHITE),
        ('FONTNAME',     (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0), 10),
        ('ALIGN',        (0,0), (-1,0), 'CENTER'),
        # Data rows
        ('FONTNAME',     (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE',     (0,1), (-1,-1), 9),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LIGHT_GREY]),
        ('TEXTCOLOR',    (0,1), (0,-1), DARK_GREY),
        ('TEXTCOLOR',    (1,1), (1,-1), BLOCK_RED),
        ('FONTNAME',     (0,1), (0,-1), 'Helvetica-Bold'),
        ('ALIGN',        (1,0), (1,-1), 'CENTER'),
        # Grid
        ('GRID',         (0,0), (-1,-1), 0.5, MID_GREY),
        ('TOPPADDING',   (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0), (-1,-1), 6),
        ('LEFTPADDING',  (0,0), (-1,-1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # Summary paragraph
    risk_level = 'CRITICAL' if blocked > 50 else 'HIGH' if blocked > 10 else 'MEDIUM' if blocked > 2 else 'LOW'
    story.append(Paragraph(
        f"During the analyzed period, SentinelShield processed <b>{total} HTTP requests</b> and "
        f"detected <b>{blocked + flagged} malicious or suspicious requests</b> ({block_rate}% block rate). "
        f"The ML anomaly detector independently identified <b>{anomalies} potential zero-day attacks</b> "
        f"with no matching signature rules. Overall risk level: <b>{risk_level}</b>.",
        style_body
    ))

    story.append(Spacer(1, 20))

    # ── Attack Type Breakdown ─────────────────────────────────────
    story.append(Paragraph("2. Attack Type Breakdown", style_section))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY, spaceAfter=10))

    if attack_dist:
        atk_header = [['Attack Category', 'Count', 'Percentage', 'Risk Level']]
        total_attacks = sum(attack_dist.values())
        risk_map = {
            'Command Injection': 'CRITICAL',
            'SQL Injection': 'HIGH',
            'Server-Side Request Forgery (SSRF)': 'HIGH',
            'Local File Inclusion / Path Traversal': 'HIGH',
            'Cross-Site Scripting (XSS)': 'MEDIUM',
        }
        atk_rows = [
            [
                cat,
                str(count),
                f"{round(count/total_attacks*100, 1)}%",
                risk_map.get(cat, 'MEDIUM')
            ]
            for cat, count in sorted(attack_dist.items(), key=lambda x: -x[1])
        ]

        atk_table = Table(atk_header + atk_rows, colWidths=[9*cm, 3*cm, 3*cm, 3*cm])
        atk_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), BLOCK_RED),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0), 10),
            ('ALIGN',         (1,0), (-1,-1), 'CENTER'),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,1), (-1,-1), 9),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LIGHT_GREY]),
            ('GRID',          (0,0), (-1,-1), 0.5, MID_GREY),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ]))
        story.append(atk_table)
    else:
        story.append(Paragraph("No attacks detected in this time window. ✅", style_body))

    story.append(Spacer(1, 20))

    # ── Top Attacking IPs ─────────────────────────────────────────
    story.append(Paragraph("3. Top Attacking IP Addresses", style_section))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY, spaceAfter=10))

    if top_ips:
        ip_header = [['Rank', 'IP Address', 'Blocked Requests', 'Recommendation']]
        ip_rows = [
            [f"#{i+1}", ip, str(count), 'Permanent ban recommended' if count > 5 else 'Monitor closely']
            for i, (ip, count) in enumerate(top_ips)
        ]

        ip_table = Table(ip_header + ip_rows, colWidths=[2*cm, 5*cm, 5*cm, 6*cm])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), DARK_GREY),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0), 10),
            ('ALIGN',         (0,0), (0,-1), 'CENTER'),
            ('ALIGN',         (2,0), (2,-1), 'CENTER'),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,1), (-1,-1), 9),
            ('TEXTCOLOR',     (1,1), (1,-1), BLOCK_RED),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LIGHT_GREY]),
            ('GRID',          (0,0), (-1,-1), 0.5, MID_GREY),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ]))
        story.append(ip_table)
    else:
        story.append(Paragraph("No attacking IPs recorded in this time window.", style_body))

    story.append(Spacer(1, 20))

    # ── Recent Attack Timeline ────────────────────────────────────
    story.append(Paragraph("4. Recent Attack Timeline", style_section))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY, spaceAfter=10))

    if recent_malicious:
        tl_header = [['Timestamp', 'IP Address', 'Verdict', 'Attack Type', 'Score']]
        tl_rows = []
        for log in recent_malicious:
            tl_rows.append([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.ip_address,
                log.verdict,
                ', '.join(log.attack_types or []) or 'Anomaly',
                str(int(log.threat_score)),
            ])

        tl_table = Table(tl_header + tl_rows, colWidths=[4.5*cm, 3.5*cm, 2.5*cm, 5*cm, 2*cm])
        tl_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#1a1a4e')),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0), 9),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,1), (-1,-1), 8),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LIGHT_GREY]),
            ('GRID',          (0,0), (-1,-1), 0.5, MID_GREY),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ]))
        story.append(tl_table)
    else:
        story.append(Paragraph("No attacks recorded in this time window.", style_body))

    story.append(PageBreak())

    # ── Recommendations ───────────────────────────────────────────
    story.append(Paragraph("5. Security Recommendations", style_section))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY, spaceAfter=10))

    recommendations = []
    if blocked > 0:
        recommendations.append(("HIGH", "Review and permanently ban top attacking IPs", f"{len(top_ips)} IPs detected with repeated attacks"))
    if anomalies > 0:
        recommendations.append(("MEDIUM", "Investigate ML-flagged zero-day attempts", f"{anomalies} anomalous requests detected without matching signatures"))
    if sev_dist.get('CRITICAL', 0) > 0:
        recommendations.append(("CRITICAL", "Immediate review of CRITICAL severity alerts", f"{sev_dist['CRITICAL']} critical incidents require immediate attention"))
    if total > 0 and block_rate < 5:
        recommendations.append(("LOW", "Consider tightening detection thresholds", "Block rate is low — may indicate missed attacks or clean traffic"))

    recommendations.append(("INFO", "Enable Redis for rate limiting", "Install Redis to activate brute-force protection"))
    recommendations.append(("INFO", "Set up Slack/Discord webhook alerts", "Configure real-time notifications for CRITICAL alerts"))
    recommendations.append(("INFO", "Schedule daily automated reports", "Run report_generator.py daily via scheduled task"))

    rec_data = [['Priority', 'Recommendation', 'Details']]
    for priority, rec, detail in recommendations:
        rec_data.append([priority, rec, detail])

    rec_colors = {'CRITICAL': CRIT_RED, 'HIGH': BLOCK_RED, 'MEDIUM': FLAG_ORG, 'LOW': ALLOW_GRN, 'INFO': ACCENT}
    rec_table = Table(rec_data, colWidths=[2.5*cm, 8*cm, 7*cm])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#1a1a4e')),
        ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,0), 10),
        ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,1), (-1,-1), 9),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0,0), (-1,-1), 0.5, MID_GREY),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('ALIGN',         (0,0), (0,-1), 'CENTER'),
        ('FONTNAME',      (0,1), (0,-1), 'Helvetica-Bold'),
    ]))

    # Color priority column
    for i, (priority, _, _) in enumerate(recommendations, 1):
        col = rec_colors.get(priority, ACCENT)
        rec_table.setStyle(TableStyle([('TEXTCOLOR', (0,i), (0,i), col)]))

    story.append(rec_table)
    story.append(Spacer(1, 20))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))
    story.append(Paragraph(
        f"Generated by SentinelShield v2.0 · Advanced Intrusion Detection System · "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M')} UTC",
        style_small
    ))

    # Build PDF
    doc.build(story)
    print(f"✅ Report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Generate SentinelShield PDF Report')
    parser.add_argument('--hours', type=int, default=24, help='Time window in hours (default: 24)')
    parser.add_argument('--output', type=str, default=None, help='Output file path')
    args = parser.parse_args()

    path = generate_report(hours=args.hours, output_path=args.output)
    if path:
        print(f"\n📄 Report saved to: {path}")
        print("   Open it with any PDF viewer!")
