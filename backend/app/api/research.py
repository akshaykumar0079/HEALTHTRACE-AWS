"""User-provided dataset workflow API (docs/user-datasets.md).

Roles: reading experiments needs the normal read access; anything that touches an uploaded file (upload, preview,
validate, run, repeat) needs the **operator** role; deleting an upload needs **admin**.

The upload is the raw request body (no multipart dependency), read in chunks and cut off at the size limit. The
server recomputes validation and results itself. Error responses carry row numbers and reason codes only.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.auth import read_access, require_admin, require_operator
from app.privacy.safe_log import safe_exc
from app.research.dataset import DatasetError
from app.research.mapping import MappingSpec
from app.research.service import IntegrityError, NotFound, ResearchService, ValidationFailed

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/research", dependencies=[Depends(read_access)])
_lock = asyncio.Lock()

_STATUS = {"unsupported_type": 415, "too_large": 413}


def _service(request: Request) -> ResearchService:
    return request.app.state.pipeline.research


def _enabled(request: Request) -> ResearchService:
    svc = _service(request)
    if not svc.settings.research_enabled:
        raise HTTPException(status_code=404, detail="User-dataset evaluation is disabled on this server.")
    return svc


def _not_found(what: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{what} not found")


def _dataset_error(exc: DatasetError) -> HTTPException:
    return HTTPException(status_code=_STATUS.get(exc.code, 422), detail={"code": exc.code, "message": exc.message})


async def _audit(request: Request, actor: str, action: str, target: str, detail: Optional[str] = None, outcome: str = "ok") -> None:
    await request.app.state.pipeline.audit(actor, action, "research", target, detail=detail, outcome=outcome)


class ValidateRequest(BaseModel):
    mapping: MappingSpec


class RunRequest(BaseModel):
    upload_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    mapping: MappingSpec
    methods: list[str] = Field(default_factory=lambda: ["current"], max_length=10)
    mode: str = "auto"
    acknowledged_privacy_warning: bool = False


@router.get("/info")
async def info(request: Request) -> dict[str, Any]:
    return _service(request).info()


@router.post("/uploads")
async def upload(request: Request, actor: str = Depends(require_operator),
                 x_filename: Optional[str] = Header(default=None),
                 x_privacy_ack: Optional[str] = Header(default=None)) -> dict[str, Any]:
    svc = _enabled(request)
    if x_privacy_ack != "yes":
        raise HTTPException(status_code=400, detail="Confirm the privacy warning before uploading (X-Privacy-Ack: yes).")
    limit = svc.max_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail={"code": "too_large", "message": f"The file is larger than the {svc.settings.research_max_upload_mb} MB limit."})
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail={"code": "too_large", "message": f"The file is larger than the {svc.settings.research_max_upload_mb} MB limit."})
        chunks.append(chunk)
    name = unquote(x_filename) if x_filename else None
    try:
        out = await asyncio.to_thread(svc.save_upload, b"".join(chunks), name, actor)
    except DatasetError as exc:
        await _audit(request, actor, "research.upload", "-", exc.code, "rejected")
        raise _dataset_error(exc) from None
    await _audit(request, actor, "research.upload", out["upload"]["id"][:16])
    return out


@router.get("/uploads/{upload_id}")
async def inspect_upload(upload_id: str, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    svc = _enabled(request)
    try:
        return await asyncio.to_thread(svc.inspect, upload_id)
    except NotFound:
        raise _not_found("upload") from None
    except DatasetError as exc:
        raise _dataset_error(exc) from None
    except IntegrityError:
        raise HTTPException(status_code=409, detail="The stored upload no longer matches its hash; it was not processed.") from None


@router.post("/uploads/{upload_id}/validate")
async def validate_upload(upload_id: str, payload: ValidateRequest, request: Request,
                          actor: str = Depends(require_operator)) -> dict[str, Any]:
    svc = _enabled(request)
    try:
        return await asyncio.to_thread(svc.validate, upload_id, payload.mapping)
    except NotFound:
        raise _not_found("upload") from None
    except DatasetError as exc:
        raise _dataset_error(exc) from None
    except IntegrityError:
        raise HTTPException(status_code=409, detail="The stored upload no longer matches its hash; it was not processed.") from None


@router.delete("/uploads/{upload_id}")
async def delete_upload(upload_id: str, request: Request, actor: str = Depends(require_admin)) -> dict[str, Any]:
    svc = _enabled(request)
    if not await asyncio.to_thread(svc.store.delete_upload, upload_id):
        raise _not_found("upload")
    await _audit(request, actor, "research.delete_upload", upload_id[:16])
    return {"deleted": True}


@router.post("/experiments")
async def run_experiment(payload: RunRequest, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    svc = _enabled(request)
    if not payload.acknowledged_privacy_warning:
        raise HTTPException(status_code=400, detail="Confirm the privacy warning before processing uploaded data.")
    if _lock.locked():
        raise HTTPException(status_code=409, detail="An evaluation is already running.")
    async with _lock:
        try:
            record = await asyncio.to_thread(svc.run, payload.upload_id, payload.mapping, payload.methods, payload.mode, actor)
        except ValidationFailed as exc:
            raise HTTPException(status_code=422, detail={"code": "validation_failed", "message": "The dataset or mapping is not valid.",
                                                         "report": exc.report}) from None
        except NotFound:
            raise _not_found("upload") from None
        except DatasetError as exc:
            raise _dataset_error(exc) from None
        except IntegrityError:
            raise HTTPException(status_code=409, detail="The stored upload no longer matches its hash; it was not processed.") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except Exception as exc:  # noqa: BLE001  - never echo the cause: it can embed a value from the file
            logger.error("research run failed: %s", safe_exc(exc))
            await _audit(request, actor, "research.run", payload.upload_id[:16], "error", "failed")
            raise HTTPException(status_code=500, detail="The evaluation failed. No details are shown to avoid exposing file content.") from None
    await _audit(request, actor, "research.run", record["id"])
    return record


@router.get("/experiments")
async def list_experiments(request: Request, limit: int = 30) -> dict[str, Any]:
    svc = _enabled(request)
    items = await asyncio.to_thread(svc.store.list_experiments, max(1, min(limit, 100)))
    return {"items": [{"id": e["id"], "created_at": e["created_at"], "created_by": e["created_by"],
                       "filename": e["upload"]["filename"], "upload_sha256": e["upload"]["sha256"],
                       "mode": e["config"]["mode"], "kind": e["config"]["mapping"]["kind"],
                       "methods": e["config"]["methods"], "results_sha256": e["results_sha256"],
                       "rerun_of": e.get("rerun_of"), "reproduced": e.get("reproduced"),
                       "incidents_found": {m["method"]: m.get("incidents_found") for m in e["result"]["methods"]}}
                      for e in items]}


@router.get("/experiments/compare")
async def compare(request: Request, a: str, b: str) -> dict[str, Any]:
    svc = _enabled(request)
    try:
        return await asyncio.to_thread(svc.compare, a, b)
    except NotFound:
        raise _not_found("experiment") from None


@router.get("/experiments/{experiment_id}")
async def get_experiment(experiment_id: str, request: Request) -> dict[str, Any]:
    svc = _enabled(request)
    try:
        return await asyncio.to_thread(svc.store.get_experiment, experiment_id)
    except NotFound:
        raise _not_found("experiment") from None


@router.post("/experiments/{experiment_id}/rerun")
async def rerun(experiment_id: str, request: Request, actor: str = Depends(require_operator)) -> dict[str, Any]:
    svc = _enabled(request)
    if _lock.locked():
        raise HTTPException(status_code=409, detail="An evaluation is already running.")
    async with _lock:
        try:
            record = await asyncio.to_thread(svc.rerun, experiment_id, actor)
        except NotFound:
            raise _not_found("experiment or its upload") from None
        except ValidationFailed:
            raise HTTPException(status_code=422, detail="The stored configuration no longer validates.") from None
        except IntegrityError:
            raise HTTPException(status_code=409, detail="The stored upload no longer matches its hash; it was not processed.") from None
        except Exception as exc:  # noqa: BLE001
            logger.error("research rerun failed: %s", safe_exc(exc))
            raise HTTPException(status_code=500, detail="The evaluation failed. No details are shown to avoid exposing file content.") from None
    await _audit(request, actor, "research.rerun", record["id"], detail=f"of {experiment_id}")
    return record
