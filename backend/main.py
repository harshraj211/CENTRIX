"""
VulnGuard Backend — FastAPI Application Entry Point

Starts the server with:
  uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import scan, findings, reports, ws

app = FastAPI(
    title="VulnGuard API",
    description="Vulnerability Scanner Backend",
    version="4.0.0",
)

# ── CORS — allow the Vite dev server (port 8443 default, also 5173) ──────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8443",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8443",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(scan.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(ws.router)


@app.get("/")
async def root():
    return {
        "name": "VulnGuard API",
        "version": "4.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
