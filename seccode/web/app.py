"""FastAPI Web Application for SecCode Mobile."""

import os
from typing import Optional, List
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from seccode.orchestrator import SecCodeOrchestrator
from seccode.models import AuditReport
from seccode.config import default_config

app = FastAPI(title="SecCode Mobile", description="OWASP Mobile Top 10 Multi-Agent Audit & Remediation Dashboard")

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# In-memory store for session reports
REPORT_CACHE: dict[str, AuditReport] = {}


class AuditRequest(BaseModel):
    repo_path: str
    scope: Optional[List[str]] = ["M1", "M5", "M9"]
    use_llm: Optional[bool] = False


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "default_repo": "/home/ubuntu/snailly-mobile",
    })


@app.post("/api/audit")
async def trigger_audit(payload: AuditRequest):
    if not os.path.exists(payload.repo_path):
        return JSONResponse(status_code=400, content={"error": f"Repository path not found: {payload.repo_path}"})

    orchestrator = SecCodeOrchestrator(default_config)
    report = orchestrator.run_audit(
        repo_path=payload.repo_path,
        categories=payload.scope,
        use_llm=payload.use_llm,
    )
    REPORT_CACHE[report.id] = report
    return report.model_dump()


@app.get("/report/{report_id}", response_class=HTMLResponse)
async def view_report(request: Request, report_id: str):
    report = REPORT_CACHE.get(report_id)
    if not report:
        return HTMLResponse("<h1>Report Not Found</h1><p>Please run an audit first.</p>", status_code=404)

    return templates.TemplateResponse("report.html", {
        "request": request,
        "report": report,
    })


@app.get("/api/reports/{report_id}/markdown")
async def download_markdown(report_id: str):
    report = REPORT_CACHE.get(report_id)
    if not report:
        return JSONResponse(status_code=404, content={"error": "Report not found"})
    md = SecCodeOrchestrator.format_markdown(report)
    return HTMLResponse(content=md, media_type="text/markdown")
