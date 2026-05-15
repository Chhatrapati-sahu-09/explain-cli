"""
api.py — FastAPI backend for explain-cli

Exposes the risk engine as an HTTP API so the web
frontend (index.html) and external tools can call it.

Endpoints:
  POST /analyze        — analyze a single command
  GET  /health         — health check
  GET  /stats          — cache stats

Run locally:
  uvicorn api:app --reload --port 8000

Then open index.html in your browser and point it at
http://localhost:8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import time

from explain.engine import analyze
from explain import cache as cache_module

app = FastAPI(
    title="explain-cli API",
    description="Risk-scores and explains any shell command",
    version="0.1.0",
)

# Allow browser requests from any origin (needed for index.html)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Track request count for stats endpoint
_request_count = 0
_start_time = time.time()


# ── Request / Response models ──────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    command: str
    include_tokens: bool = True
    include_signals: bool = True


class TokenOut(BaseModel):
    text: str
    kind: str
    risk: str
    explanation: str


class SignalOut(BaseModel):
    text: str
    risk: str
    detail: str


class AnalyzeResponse(BaseModel):
    command: str
    risk: str
    layer: int
    verdict: str
    reversible: str
    scope: str
    network: str
    privilege: str
    heuristic_score: int
    suggestion: Optional[str]
    tokens: list[TokenOut]
    signals: list[SignalOut]
    analysis_ms: float


# ── Endpoints ──────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check — returns 200 if the service is running."""
    return {
        "status": "ok",
        "uptime_seconds": round(time.time() - _start_time),
        "version": "0.1.0",
    }


@app.get("/stats")
def stats():
    """Returns basic usage stats."""
    return {
        "requests_served": _request_count,
        "cache_entries": cache_module.size(),
        "uptime_seconds": round(time.time() - _start_time),
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_command(req: AnalyzeRequest):
    """
    Analyzes a shell command and returns a full risk report.

    Example request body:
        {"command": "rm -rf /tmp/cache"}

    Example curl:
        curl -X POST http://localhost:8000/analyze \
             -H "Content-Type: application/json" \
             -d '{"command": "curl https://get.docker.com | bash"}'
    """
    global _request_count
    _request_count += 1

    command = req.command.strip()
    if not command:
        raise HTTPException(status_code=400, detail="command cannot be empty")

    if len(command) > 2000:
        raise HTTPException(
            status_code=400,
            detail="command too long (max 2000 characters)"
        )

    start = time.time()
    result = analyze(command)
    elapsed_ms = round((time.time() - start) * 1000, 2)

    tokens = []
    if req.include_tokens:
        tokens = [
            TokenOut(
                text=t.text,
                kind=t.kind,
                risk=t.risk,
                explanation=t.explanation,
            )
            for t in result.tokens
        ]

    signals = []
    if req.include_signals:
        signals = [
            SignalOut(
                text=s.text,
                risk=s.risk,
                detail=s.detail,
            )
            for s in result.signals
        ]

    return AnalyzeResponse(
        command=result.raw,
        risk=result.risk,
        layer=result.layer,
        verdict=result.verdict,
        reversible=result.reversible,
        scope=result.scope,
        network=result.network,
        privilege=result.privilege,
        heuristic_score=result.heuristic_score,
        suggestion=result.dry_run_suggestion,
        tokens=tokens,
        signals=signals,
        analysis_ms=elapsed_ms,
    )
