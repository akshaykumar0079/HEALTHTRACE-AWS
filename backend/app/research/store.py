"""File store for uploads and experiment records.

* An upload is stored **byte-for-byte as received**, under its own SHA-256 (``uploads/<sha256>.<ext>``). It is
  written once, marked read-only, and verified against its hash every time it is read. Nothing ever rewrites it.
* An experiment record is one JSON file (``experiments/<id>.json``) holding the exact configuration, the upload's
  hash and the results, so a run can be repeated and compared. Records contain pseudonymized entities and
  timestamps, never raw rows.
* Retention (``purge``) removes records and uploads older than the configured number of days; an upload that a
  newer experiment still refers to is kept until that experiment expires.
* Ids are validated against fixed patterns, so a request can never name a path.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from app.ingest.pseudonym import IngestConfigError, Pseudonymizer, load_key
from app.research.dataset import sha256_hex

UPLOAD_ID = re.compile(r"^[0-9a-f]{64}$")
EXPERIMENT_ID = re.compile(r"^exp-\d{8}T\d{6}Z-[0-9a-f]{8}(?:-\d+)?$")


class NotFound(LookupError):
    pass


class IntegrityError(RuntimeError):
    """A stored upload no longer matches its hash. Nothing is processed."""


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _readonly(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IREAD)
    except OSError:
        pass


class ResearchStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.uploads = self.root / "uploads"
        self.experiments = self.root / "experiments"

    # -- uploads --------------------------------------------------------------------------------

    def save_upload(self, data: bytes, *, ext: str, filename: str, fmt: str, uploaded_by: str,
                    now: Optional[datetime] = None) -> dict[str, Any]:
        digest = sha256_hex(data)
        blob = self.uploads / f"{digest}{ext}"
        meta_path = self.uploads / f"{digest}.json"
        if meta_path.exists() and blob.exists():
            return json.loads(meta_path.read_text(encoding="utf-8"))          # identical bytes: already stored
        if blob.exists():
            self._unlink(blob)                                                 # leftover without metadata
        _atomic_write(blob, data)
        _readonly(blob)
        meta = {"id": digest, "ext": ext, "filename": filename, "format": fmt, "size_bytes": len(data),
                "uploaded_at": (now or datetime.now(timezone.utc)).isoformat(), "uploaded_by": uploaded_by}
        _atomic_write(meta_path, json.dumps(meta, indent=2).encode("utf-8"))
        return meta

    def upload_meta(self, upload_id: str) -> dict[str, Any]:
        if not UPLOAD_ID.match(upload_id):
            raise NotFound("upload")
        path = self.uploads / f"{upload_id}.json"
        if not path.is_file():
            raise NotFound("upload")
        return json.loads(path.read_text(encoding="utf-8"))

    def read_upload(self, upload_id: str) -> tuple[bytes, dict[str, Any]]:
        meta = self.upload_meta(upload_id)
        blob = self.uploads / f"{upload_id}{meta['ext']}"
        if not blob.is_file():
            raise NotFound("upload")
        data = blob.read_bytes()
        if sha256_hex(data) != upload_id:
            raise IntegrityError("stored upload does not match its hash")
        return data, meta

    def delete_upload(self, upload_id: str) -> bool:
        """Remove an upload and every experiment that used it (the privacy 'delete my data' action)."""
        try:
            meta = self.upload_meta(upload_id)
        except NotFound:
            return False
        for exp in self.list_experiments(limit=100_000):
            if exp["upload"]["sha256"] == upload_id:
                self._remove_experiment(exp["id"])
        for path in (self.uploads / f"{upload_id}{meta['ext']}", self.uploads / f"{upload_id}.json"):
            self._unlink(path)
        return True

    @staticmethod
    def _unlink(path: Path) -> None:
        try:
            os.chmod(path, stat.S_IWRITE)
            path.unlink()
        except OSError:
            pass

    # -- experiments ----------------------------------------------------------------------------------

    def new_experiment_id(self, fingerprint: str, now: Optional[datetime] = None) -> str:
        stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
        base = f"exp-{stamp}-{fingerprint[:8]}"
        candidate, n = base, 1
        while (self.experiments / f"{candidate}.json").exists():
            n += 1
            candidate = f"{base}-{n}"
        return candidate

    def save_experiment(self, record: dict[str, Any]) -> None:
        if not EXPERIMENT_ID.match(record["id"]):
            raise ValueError("bad experiment id")
        _atomic_write(self.experiments / f"{record['id']}.json", json.dumps(record, indent=2).encode("utf-8"))

    def get_experiment(self, experiment_id: str) -> dict[str, Any]:
        if not EXPERIMENT_ID.match(experiment_id):
            raise NotFound("experiment")
        path = self.experiments / f"{experiment_id}.json"
        if not path.is_file():
            raise NotFound("experiment")
        return json.loads(path.read_text(encoding="utf-8"))

    def list_experiments(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.experiments.is_dir():
            return []
        out = []
        for path in sorted(self.experiments.glob("exp-*.json"), reverse=True):
            try:
                out.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
            if len(out) >= limit:
                break
        return out

    def _remove_experiment(self, experiment_id: str) -> None:
        self._unlink(self.experiments / f"{experiment_id}.json")

    # -- retention --------------------------------------------------------------------------------------

    def purge(self, days: int, *, now: Optional[datetime] = None, dry_run: bool = False) -> dict[str, int]:
        """Delete experiments and unreferenced uploads older than ``days`` (0 = keep forever)."""
        result = {"research_experiments": 0, "research_uploads": 0}
        if days <= 0 or not self.root.is_dir():
            return result
        cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).isoformat()
        keep_refs: set[str] = set()
        expired: list[str] = []
        for exp in self.list_experiments(limit=1_000_000):
            if exp.get("created_at", "") < cutoff:
                expired.append(exp["id"])
            else:
                keep_refs.add(exp["upload"]["sha256"])
        result["research_experiments"] = len(expired)
        if not dry_run:
            for eid in expired:
                self._remove_experiment(eid)
        if self.uploads.is_dir():
            for meta_path in self.uploads.glob("*.json"):
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if meta.get("uploaded_at", "") < cutoff and meta["id"] not in keep_refs:
                    result["research_uploads"] += 1
                    if not dry_run:
                        self._unlink(self.uploads / f"{meta['id']}{meta['ext']}")
                        self._unlink(meta_path)
        return result

    # -- pseudonym key ----------------------------------------------------------------------------------

    def pseudonymizer(self, configured_key: Optional[str]) -> Pseudonymizer:
        """The configured PSEUDONYM_KEY if there is one; otherwise a random key created once for this
        installation and kept in a private file next to the data (never in an experiment record or a log). The
        same key means the same pseudonyms, which is what lets an experiment be repeated and compared."""
        if configured_key and configured_key.strip():
            return Pseudonymizer(load_key(configured_key))
        path = self.root / ".pseudonym_key"
        try:
            if path.is_file():
                return Pseudonymizer(load_key(path.read_text(encoding="utf-8")))
            key = secrets.token_hex(32)
            self.root.mkdir(parents=True, exist_ok=True)
            path.write_text(key, encoding="utf-8")
            try:
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            except OSError:
                pass
            return Pseudonymizer(load_key(key))
        except (OSError, IngestConfigError) as exc:
            raise IngestConfigError("could not obtain a pseudonymization key for uploaded data") from exc
