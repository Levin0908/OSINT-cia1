"""FastAPI application factory + routes."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config
from core.database import Database
from core.investigator import Investigator
from core.models import InvestigationRequest, InvestigationResult
from core.report import ReportGenerator

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title="OSINT Phishing Investigation Platform",
        description="Automated OSINT collection and phishing risk analysis.",
        version="1.0.0",
    )
    db = Database()
    investigator = Investigator(db=db)
    reporter = ReportGenerator()

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # ------------------------------------------------------------------
    # pages
    # ------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        stats = db.statistics()
        recent = db.list_investigations(limit=10)
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {"stats": stats, "recent": recent},
        )

    @app.get("/investigate", response_class=HTMLResponse)
    async def investigate_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "investigate.html", {})

    @app.get("/report/{investigation_id}", response_class=HTMLResponse)
    async def report_page(request: Request, investigation_id: int) -> HTMLResponse:
        result = db.get_investigation(investigation_id)
        if not result:
            raise HTTPException(404, "Investigation not found")
        return templates.TemplateResponse(request, "report.html", {"result": result})

    @app.get("/history", response_class=HTMLResponse)
    async def history_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "history.html",
            {"investigations": db.list_investigations(limit=200)},
        )

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------
    @app.post("/api/investigate", response_model=InvestigationResult)
    async def api_investigate(payload: InvestigationRequest) -> InvestigationResult:
        if not payload.target or len(payload.target) > 2048:
            raise HTTPException(400, "Target must be a non-empty URL/domain <= 2048 chars")
        result = investigator.investigate(payload)
        return result

    @app.get("/api/investigations")
    async def api_list_investigations(limit: int = 50) -> List[dict]:
        return db.list_investigations(limit=limit)

    @app.get("/api/investigations/{investigation_id}", response_model=InvestigationResult)
    async def api_get_investigation(investigation_id: int) -> InvestigationResult:
        result = db.get_investigation(investigation_id)
        if not result:
            raise HTTPException(404, "Investigation not found")
        return result

    @app.get("/api/investigations/{investigation_id}/report")
    async def api_report(investigation_id: int, format: str = "json") -> PlainTextResponse:
        result = db.get_investigation(investigation_id)
        if not result:
            raise HTTPException(404, "Investigation not found")
        if format == "markdown":
            return PlainTextResponse(reporter.to_markdown(result), media_type="text/markdown")
        if format == "pdf":
            path = reporter.to_pdf(result)
            return JSONResponse({"path": str(path), "format": "pdf"})
        return PlainTextResponse(reporter.to_json(result), media_type="application/json")

    @app.get("/api/ioc/search")
    async def api_ioc_search(value: str) -> List[dict]:
        return db.search_iocs(value)

    @app.get("/api/stats")
    async def api_stats() -> dict:
        return db.statistics()

    @app.get("/api/health")
    async def api_health() -> dict:
        return {"status": "ok", "service": "OSINT Phishing Investigator"}

    return app


app = create_app()
