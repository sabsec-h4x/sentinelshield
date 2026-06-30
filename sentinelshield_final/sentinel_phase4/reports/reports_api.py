# ─────────────────────────────────────────────────────────────────
#  api/reports.py — Report Generation API Endpoint
#
#  ADD THIS to your main.py:
#    from api.reports import router as reports_router
#    app.include_router(reports_router)
#
#  ENDPOINTS:
#    POST /api/reports/generate   → Generate and download PDF
#    GET  /api/reports/list       → List all generated reports
# ─────────────────────────────────────────────────────────────────

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os, sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

router = APIRouter(prefix="/api/reports", tags=["Reports"])

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "generated_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportRequest(BaseModel):
    hours: int = 24


@router.post("/generate")
async def generate_report(req: ReportRequest):
    """Generate a PDF security report and return download link."""
    try:
        from reports.report_generator import generate_report as gen

        date_str = datetime.now().strftime('%Y-%m-%d_%H-%M')
        filename = f"sentinelshield_report_{date_str}.pdf"
        filepath = os.path.join(REPORTS_DIR, filename)

        path = gen(hours=req.hours, output_path=filepath)

        if path and os.path.exists(path):
            return {
                "message":   "Report generated successfully",
                "filename":  filename,
                "download":  f"/api/reports/download/{filename}",
                "hours":     req.hours,
                "generated": datetime.now().isoformat(),
            }
        else:
            raise HTTPException(status_code=500, detail="Report generation failed. Is reportlab installed?")

    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="reportlab not installed. Run: pip install reportlab"
        )


@router.get("/download/{filename}")
async def download_report(filename: str):
    """Download a generated report."""
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        filepath,
        media_type   = "application/pdf",
        filename     = filename,
    )


@router.get("/list")
async def list_reports():
    """List all generated reports."""
    files = []
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if f.endswith('.pdf'):
            path = os.path.join(REPORTS_DIR, f)
            files.append({
                "filename": f,
                "size_kb":  round(os.path.getsize(path) / 1024, 1),
                "created":  datetime.fromtimestamp(os.path.getctime(path)).isoformat(),
                "download": f"/api/reports/download/{f}",
            })
    return {"reports": files, "total": len(files)}
