"""Database adapters: SQLite (local default) and PostgreSQL (hosted).

``Store`` writes every statement once, with ``?`` placeholders and the SQL
subset both engines share (``ON CONFLICT ... DO UPDATE``, ``COALESCE``,
``substr``). This module hides the remaining differences:

* placeholders (``?`` -> ``%s`` for psycopg),
* generated ids (``cursor.lastrowid`` vs ``RETURNING id``),
* column/table introspection (used by the migration runner),
* connection loss: the PostgreSQL adapter reconnects, because free hosted
  databases close idle connections.

Every value reaches the driver as a bound parameter; nothing is formatted
into SQL text except identifiers chosen by code (never by a request).
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any, Optional, Sequence

import aiosqlite

log = logging.getLogger("healthtrace.db")

Params = Sequence[Any]


def normalize_database_url(url: str) -> str:
    """Accept the spellings hosting providers hand out (``postgres://``,
    ``postgresql+psycopg://``) and return one psycopg understands."""
    url = url.strip()
    url = re.sub(r"^postgres(ql)?(\+\w+)?://", "postgresql://", url)
    return url


def is_postgres_url(url: Optional[str]) -> bool:
    return bool(url) and re.match(r"^postgres(ql)?(\+\w+)?://", url.strip()) is not None  # type: ignore[union-attr]


def redact_database_url(url: str) -> str:
    """``postgresql://user:***@host/db`` - safe for logs and the status API."""
    return re.sub(r"://([^:/@]+):[^@]*@", r"://\1:***@", url)


class Database:
    """Common interface. ``dialect`` is ``"sqlite"`` or ``"postgres"``."""

    dialect = "sqlite"

    async def connect(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def close(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def execute(self, sql: str, params: Params = ()) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    async def executemany(self, sql: str, rows: Sequence[Params]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def commit(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def insert(self, sql: str, params: Params = ()) -> int:  # pragma: no cover - interface
        """Run an INSERT into a table whose primary key is ``id`` and return it."""
        raise NotImplementedError

    async def column_names(self, table: str) -> set[str]:  # pragma: no cover - interface
        raise NotImplementedError

    async def table_exists(self, table: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    async def ping(self) -> None:
        await self.execute("SELECT 1")

    # Dialect fragments used by the schema builder.
    @property
    def pk(self) -> str:
        return "INTEGER PRIMARY KEY AUTOINCREMENT"

    @property
    def real(self) -> str:
        return "REAL"

    @property
    def bigint(self) -> str:
        return "INTEGER"

    async def add_column_if_missing(self, table: str, column: str, ddl_type: str) -> bool:
        if column in await self.column_names(table):
            return False
        await self.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")
        return True

    async def run_script(self, script: str) -> None:
        """Run ``;``-separated DDL statements (no ``;`` inside a statement)."""
        for statement in (s.strip() for s in script.split(";")):
            if statement:
                await self.execute(statement)


class SqliteDatabase(Database):
    dialect = "sqlite"

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        # WAL + NORMAL: commits no longer fsync, which is what capped the
        # pipeline at ~100 writes/sec during replay and alert bursts.
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA busy_timeout=5000")

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Store is not connected; call connect() first")
        return self._conn

    async def execute(self, sql: str, params: Params = ()) -> aiosqlite.Cursor:
        return await self.conn.execute(sql, tuple(params))

    async def executemany(self, sql: str, rows: Sequence[Params]) -> None:
        await self.conn.executemany(sql, [tuple(r) for r in rows])

    async def commit(self) -> None:
        await self.conn.commit()

    async def insert(self, sql: str, params: Params = ()) -> int:
        cursor = await self.conn.execute(sql, tuple(params))
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    async def column_names(self, table: str) -> set[str]:
        cursor = await self.conn.execute(f"PRAGMA table_info({table})")
        return {row[1] for row in await cursor.fetchall()}

    async def table_exists(self, table: str) -> bool:
        cursor = await self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (table,))
        return await cursor.fetchone() is not None


class _Rows:
    """Result of a PostgreSQL statement, materialised under the connection lock
    so callers can use the same ``await cursor.fetchall()`` shape as aiosqlite."""

    def __init__(self, rows: list[tuple], lastrowid: Optional[int] = None) -> None:
        self._rows = rows
        self.lastrowid = lastrowid

    async def fetchall(self) -> list[tuple]:
        return self._rows

    async def fetchone(self) -> Optional[tuple]:
        return self._rows[0] if self._rows else None


class PostgresDatabase(Database):
    dialect = "postgres"

    def __init__(self, url: str, *, connect_timeout: int = 10) -> None:
        self.url = normalize_database_url(url)
        self.connect_timeout = connect_timeout
        self._conn: Any = None
        self._lock = asyncio.Lock()

    @property
    def pk(self) -> str:
        return "BIGSERIAL PRIMARY KEY"

    @property
    def real(self) -> str:
        return "DOUBLE PRECISION"

    @property
    def bigint(self) -> str:
        return "BIGINT"

    async def connect(self) -> None:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - depends on install
            raise RuntimeError(
                "DATABASE_URL points at PostgreSQL but the driver is missing: pip install 'psycopg[binary]'"
            ) from exc
        # autocommit: every Store call is one statement/one transaction, as with
        # the per-call commit() used for SQLite. A failed statement therefore
        # never leaves a half-open transaction behind.
        self._conn = await psycopg.AsyncConnection.connect(
            self.url, autocommit=True, connect_timeout=self.connect_timeout
        )

    async def close(self) -> None:
        if self._conn is not None:
            try:
                await self._conn.close()
            finally:
                self._conn = None

    async def _ensure(self) -> Any:
        if self._conn is None or self._conn.closed:
            log.warning("database connection lost; reconnecting")
            await self.connect()
        return self._conn

    @staticmethod
    def _translate(sql: str) -> str:
        return sql.replace("%", "%%").replace("?", "%s")

    async def _run(self, sql: str, params: Params, *, many: bool = False, want_rows: bool = True) -> list[tuple]:
        import psycopg

        text = self._translate(sql)
        async with self._lock:
            for attempt in (1, 2):
                try:
                    conn = await self._ensure()
                    async with conn.cursor() as cur:
                        if many:
                            await cur.executemany(text, [tuple(p) for p in params])  # type: ignore[arg-type]
                            return []
                        await cur.execute(text, tuple(params))
                        return list(await cur.fetchall()) if want_rows and cur.description else []
                except (psycopg.OperationalError, psycopg.InterfaceError):
                    # Closed/idle-killed connection: reconnect once, then give up.
                    await self.close()
                    if attempt == 2:
                        raise
        return []  # pragma: no cover

    async def execute(self, sql: str, params: Params = ()) -> _Rows:
        return _Rows(await self._run(sql, params))

    async def executemany(self, sql: str, rows: Sequence[Params]) -> None:
        await self._run(sql, rows, many=True)  # type: ignore[arg-type]

    async def commit(self) -> None:  # autocommit
        return None

    async def insert(self, sql: str, params: Params = ()) -> int:
        rows = await self._run(sql.rstrip().rstrip(";") + " RETURNING id", params)
        return int(rows[0][0])

    async def column_names(self, table: str) -> set[str]:
        rows = await self._run(
            "SELECT CAST(column_name AS TEXT) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ?",
            (table,),
        )
        return {r[0] for r in rows}

    async def table_exists(self, table: str) -> bool:
        rows = await self._run(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?",
            (table,),
        )
        return bool(rows)


def create_database(db_path: Path | str, database_url: Optional[str] = None) -> Database:
    if database_url and is_postgres_url(database_url):
        return PostgresDatabase(database_url)
    if database_url and database_url.strip() and not database_url.strip().startswith("sqlite"):
        raise ValueError("DATABASE_URL must be a postgres:// / postgresql:// URL (or empty for local SQLite)")
    if database_url and database_url.strip().startswith("sqlite"):
        # sqlite:///relative/path.db or sqlite:////abs/path.db
        db_path = re.sub(r"^sqlite(\+\w+)?:///", "", database_url.strip())
    return SqliteDatabase(db_path)
