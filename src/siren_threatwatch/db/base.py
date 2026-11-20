"""Engine/session management and secure local storage setup."""

from __future__ import annotations

import contextlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from siren_threatwatch.config import Settings, get_settings


def secure_mkdir(path: Path) -> Path:
    """Create a directory readable only by the current user (best-effort on Windows)."""
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):  # e.g. Windows ACLs / foreign-owned dirs
        os.chmod(path, stat.S_IRWXU)
    return path


def secure_file(path: Path) -> None:
    """Restrict a file to owner read/write (best-effort on Windows)."""
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _sqlite_path(url: str) -> Path | None:
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite" or not parsed.database or parsed.database == ":memory:":
        return None
    return Path(parsed.database)


def create_db_engine(url: str | None = None, settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    url = url or settings.database_url
    kwargs: dict[str, Any] = {"future": True}
    sqlite_file = _sqlite_path(url)
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    if sqlite_file is not None:
        secure_mkdir(sqlite_file.parent if str(sqlite_file.parent) else Path("."))
    engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            if sqlite_file is not None:
                cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    if sqlite_file is not None:
        # Touch the file so permissions can be applied before data is written.
        with engine.connect():
            pass
        secure_file(sqlite_file)
    return engine


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, _session_factory
    if _engine is None:
        _engine = create_db_engine()
        _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def set_engine(engine: Engine) -> None:
    """Override the global engine (used by tests)."""
    global _engine, _session_factory
    _engine = engine
    _session_factory = sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    assert _session_factory is not None
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
