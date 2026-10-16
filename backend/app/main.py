"""FastAPI app: startup/shutdown of the pipeline tasks (SPEC.md section 3),
the REST + WebSocket API, and (when built) the frontend on the same origin."""

from __future__ import annotations

import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api.research import router as research_router
from app.api.routes import router as api_router
from app.api.ws import router as ws_router
from app.config import AppConfig, Settings, get_settings, load_config
from app.pipeline import Pipeline
from app.privacy.safe_log import safe_exc

logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

_WRITE_LIMIT_PER_MIN = 120

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def create_app(settings: Optional[Settings] = None, config: Optional[AppConfig] = None) -> FastAPI:
    """settings/config are injectable so tests can point the pipeline at an
    isolated temp directory instead of the real data/ directory."""
    settings = settings or get_settings()
    config = config or load_config()
    pipeline = Pipeline(settings, config)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        generator = None
        if settings.embedded_generator:
            from app.embedded_generator import EmbeddedGenerator
            from app.config import REPO_ROOT

            generator = EmbeddedGenerator(
                log_dir=settings.log_dir, control_file=settings.control_file, root=REPO_ROOT,
                rate=settings.embedded_rate, backfill_hours=settings.embedded_backfill_hours,
            )
            # Backfill first so the baseline has history before the pipeline tails.
            await generator.start()
        await pipeline.start()
        try:
            yield
        finally:
            await pipeline.stop()
            if generator is not None:
                await generator.stop()

    app = FastAPI(title="HEALTH TRACE (MedGuard engine)", lifespan=lifespan)
    app.state.pipeline = pipeline

    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=origins, allow_credentials=False,
            allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type", "X-Operator-Token"],
        )

    # Minimal in-memory limiter for state-changing calls (per client IP).
    # Hosted single instance only; a real deployment would limit at the edge.
    hits: dict[str, deque] = {}

    @app.middleware("http")
    async def rate_limit(request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH") and request.url.path.startswith("/api/"):
            ip = request.client.host if request.client else "?"
            now = time.monotonic()
            q = hits.setdefault(ip, deque())
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= _WRITE_LIMIT_PER_MIN:
                return JSONResponse({"detail": "Too many requests; slow down."}, status_code=429,
                                    headers={"Retry-After": "30"})
            q.append(now)
            if len(hits) > 5000:
                hits.clear()
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default body echoes the offending input value back; keep only where and why.
        detail = [{"loc": list(e.get("loc", ())), "msg": e.get("msg", "invalid"), "type": e.get("type", "invalid")}
                  for e in exc.errors()]
        return JSONResponse({"detail": detail}, status_code=422)

    @app.middleware("http")
    async def error_boundary(request: Request, call_next):
        """An unhandled error becomes a generic 500. The exception text, which may
        embed the value that caused it, is neither returned nor logged: only the
        exception type and code location are."""
        try:
            return await call_next(request)
        except Exception as exc:  # noqa: BLE001
            logger.error("unhandled error on %s %s: %s", request.method, request.url.path, safe_exc(exc))
            return JSONResponse({"detail": "Internal server error"}, status_code=500)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    app.include_router(api_router, prefix="/api")
    app.include_router(research_router, prefix="/api")
    app.include_router(ws_router)
    _mount_frontend(app, settings.static_dir)
    return app


def _mount_frontend(app: FastAPI, static_dir: Path) -> None:
    index = static_dir / "index.html"
    if not index.is_file():
        return
    assets = static_dir / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    root = static_dir.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> FileResponse:
        if path.startswith(("api/", "ws")):
            raise HTTPException(status_code=404)
        candidate = (static_dir / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        # Client-side routes: let the SPA router handle them; never cache the shell.
        return FileResponse(index, headers={"Cache-Control": "no-cache"})


app = create_app()
