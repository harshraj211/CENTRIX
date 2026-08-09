"""
VulnGuard Backend — FastAPI Application Entry Point

Starts the server with:
  uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import scan, findings, reports, ws, manual, imports, evidence, integrations, proof, authz, oob, schedules

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
app.include_router(manual.router)
app.include_router(imports.router)
app.include_router(evidence.router)
app.include_router(integrations.router)
app.include_router(proof.router)
app.include_router(authz.router)
app.include_router(oob.router)
app.include_router(schedules.router)


@app.on_event("startup")
async def start_local_scheduler():
    asyncio.create_task(schedules.scheduler_loop())


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
