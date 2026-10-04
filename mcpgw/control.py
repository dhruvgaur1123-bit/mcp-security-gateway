"""FastAPI control plane: audit log, stats, policy view, and the approval inbox."""
from __future__ import annotations

import threading

from fastapi import FastAPI, HTTPException

from .approvals import ApprovalQueue
from .audit import Audit
from .policy import Policy


def create_app(policy: Policy, audit: Audit, approvals: ApprovalQueue) -> FastAPI:
    app = FastAPI(title="MCP Security Gateway", version="0.1.0")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/stats")
    def stats():
        return audit.stats()

    @app.get("/audit")
    def get_audit(limit: int = 50):
        return audit.tail(max(1, min(limit, 1000)))

    @app.get("/policy")
    def get_policy():
        return policy.to_dict()

    @app.get("/approvals")
    def list_approvals():
        return approvals.pending()

    @app.post("/approvals/{aid}/approve")
    def approve(aid: str):
        if not approvals.resolve(aid, True):
            raise HTTPException(404, "no such pending approval")
        return {"id": aid, "approved": True}

    @app.post("/approvals/{aid}/deny")
    def deny(aid: str):
        if not approvals.resolve(aid, False):
            raise HTTPException(404, "no such pending approval")
        return {"id": aid, "approved": False}

    return app


def serve_in_background(app: FastAPI, host: str, port: int) -> None:
    import uvicorn  # imported lazily so the proxy has no hard dependency on a web server

    cfg = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    threading.Thread(target=uvicorn.Server(cfg).run, daemon=True).start()
