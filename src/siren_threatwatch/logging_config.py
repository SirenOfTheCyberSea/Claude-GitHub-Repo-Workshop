"""Structured logging with secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

_SENSITIVE_KEY = re.compile(r"(api[_-]?key|auth[_-]?key|token|secret|password|authorization)", re.I)
_SENSITIVE_INLINE = re.compile(
    r"(?i)((?:api[_-]?key|auth[_-]?key|token|secret|password|authorization)\s*[=:]\s*)([^\s,;&\"']+)"
)
_RESERVED = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}


class RedactingFilter(logging.Filter):
    """Masks configured secret values and ``key=value`` style secrets in every log record."""

    def __init__(self, secrets: list[str] | None = None) -> None:
        super().__init__()
        self._secrets = [s for s in (secrets or []) if len(s) >= 4]

    def _scrub(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "***REDACTED***")
        return _SENSITIVE_INLINE.sub(r"\1***REDACTED***", text)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._scrub(record.getMessage())
        record.args = ()
        for key, value in list(vars(record).items()):
            if key in _RESERVED:
                continue
            if _SENSITIVE_KEY.search(key):
                setattr(record, key, "***REDACTED***")
            elif isinstance(value, str):
                setattr(record, key, self._scrub(value))
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value if isinstance(value, (str, int, float, bool, type(None))) else str(value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class KeyValueFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {k: v for k, v in vars(record).items() if k not in _RESERVED and not k.startswith("_")}
        if extras:
            base += " " + " ".join(f"{k}={v}" for k, v in extras.items())
        return base


def configure_logging(level: str = "INFO", json_logs: bool = False, secrets: list[str] | None = None) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_siren", False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler._siren = True  # type: ignore[attr-defined]
    handler.addFilter(RedactingFilter(secrets))
    handler.setFormatter(
        JsonFormatter()
        if json_logs
        else KeyValueFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(level)
    # httpx logs full URLs at INFO, which could include query-string credentials in later phases.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
