"""A defensive HTTP client for feed collection.

Protections
-----------
* **SSRF**: only ``https`` URLs on an explicit host allowlist; IP-literal hosts and URL user-info are
  refused; redirects are followed manually and every hop is re-checked against the allowlist.
* **Resource limits**: connect/read timeouts, maximum response size (streamed, aborted early),
  bounded concurrency, a per-client request budget, bounded redirects.
* **Resilience**: retries with exponential backoff + jitter for transport errors, HTTP 429 and 5xx;
  ``Retry-After`` honoured up to a ceiling.
* **Caching**: ETag / Last-Modified conditional requests with an on-disk cache (owner-only perms).
* Credentials passed in headers are never logged.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import random
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from siren_threatwatch import USER_AGENT
from siren_threatwatch.config import Settings
from siren_threatwatch.db.base import secure_file, secure_mkdir

log = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
MAX_RETRY_AFTER_SECONDS = 120.0
MAX_BACKOFF_SECONDS = 60.0


class HttpFetchError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, url: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.url = url


class DisallowedUrlError(HttpFetchError):
    pass


class RateLimitedError(HttpFetchError):
    pass


class ResponseTooLargeError(HttpFetchError):
    pass


class RequestBudgetExceededError(HttpFetchError):
    pass


@dataclass(slots=True)
class HttpResult:
    url: str  # final URL after redirects
    status: int
    content: bytes
    headers: dict[str, str] = field(default_factory=dict)
    from_cache: bool = False

    def json(self) -> Any:
        return json.loads(self.content)


def check_url(url: str, allowed_hosts: Iterable[str]) -> str:
    """Validate that ``url`` is safe to request. Returns the URL or raises :class:`DisallowedUrlError`."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise DisallowedUrlError(f"only https URLs are allowed (got {parts.scheme!r})", url=url)
    if not host:
        raise DisallowedUrlError("URL has no host", url=url)
    if parts.username or parts.password:
        raise DisallowedUrlError("URLs with embedded credentials are not allowed", url=url)
    try:
        ipaddress.ip_address(host.strip("[]"))
        raise DisallowedUrlError("IP-literal hosts are not allowed", url=url)
    except ValueError:
        pass
    if host not in {h.lower() for h in allowed_hosts}:
        raise DisallowedUrlError(f"host {host!r} is not on the connector allowlist", url=url)
    if parts.port not in (None, 443):
        raise DisallowedUrlError("non-standard ports are not allowed", url=url)
    return url


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        from datetime import UTC, datetime

        return max(0.0, (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds())
    except (TypeError, ValueError):
        return None


def _error_text(result: HttpResult) -> str:
    """'HTTP 404' plus the provider's explanatory ``message`` header (NVD uses one), sanitised."""
    text = f"HTTP {result.status}"
    message = result.headers.get("message")
    if message:
        clean = "".join(ch for ch in message if ch.isprintable())[:300]
        text += f": {clean}"
    return text


class _DiskCache:
    def __init__(self, directory: Path) -> None:
        self.dir = directory

    def _paths(self, url: str) -> tuple[Path, Path]:
        digest = hashlib.sha256(url.encode()).hexdigest()
        return self.dir / f"{digest}.meta.json", self.dir / f"{digest}.body"

    def load(self, url: str) -> tuple[dict[str, str], bytes] | None:
        meta_path, body_path = self._paths(url)
        if not (meta_path.exists() and body_path.exists()):
            return None
        try:
            return json.loads(meta_path.read_text("utf-8")), body_path.read_bytes()
        except (OSError, ValueError):
            return None

    def store(self, url: str, headers: dict[str, str], body: bytes) -> None:
        secure_mkdir(self.dir)
        meta_path, body_path = self._paths(url)
        keep = {k: v for k, v in headers.items() if k.lower() in ("etag", "last-modified", "content-type")}
        body_path.write_bytes(body)
        meta_path.write_text(json.dumps({"url": url, **keep}), "utf-8")
        secure_file(body_path)
        secure_file(meta_path)


class SafeHttpClient:
    def __init__(
        self,
        settings: Settings,
        allowed_hosts: Iterable[str],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        max_requests: int = 200,
        use_cache: bool = True,
        max_bytes: int | None = None,
        min_interval: float = 0.0,
        extra_retry_status: Iterable[int] = (),
    ) -> None:
        self.settings = settings
        self._max_bytes = max_bytes or settings.max_response_bytes
        self._min_interval = min_interval  # seconds between request starts (provider rate limits)
        self._last_request: float | None = None
        self._retry_status = RETRYABLE_STATUS | frozenset(extra_retry_status)
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self._sleep = sleep
        self._semaphore = asyncio.Semaphore(settings.http_max_concurrency)
        self._max_requests = max_requests
        self.requests_made = 0
        self._cache = _DiskCache(settings.cache_dir) if use_cache else None
        timeout = httpx.Timeout(
            settings.http_timeout_seconds, connect=min(10.0, settings.http_timeout_seconds)
        )
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5"},
            transport=transport,
            limits=httpx.Limits(max_connections=settings.http_max_concurrency),
        )

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResult:
        check_url(url, self.allowed_hosts)
        cached = self._cache.load(url) if self._cache else None
        req_headers = dict(headers or {})
        if cached:
            meta, _ = cached
            if meta.get("etag"):
                req_headers["If-None-Match"] = meta["etag"]
            if meta.get("last-modified"):
                req_headers["If-Modified-Since"] = meta["last-modified"]

        async with self._semaphore:
            result = await self._get_with_retries(url, req_headers)

        if result.status == 304 and cached:
            return HttpResult(
                url=result.url, status=304, content=cached[1], headers=cached[0], from_cache=True
            )
        if result.status == 304:
            # Server says "not modified" but we have nothing cached: refetch unconditionally.
            async with self._semaphore:
                result = await self._get_with_retries(url, dict(headers or {}))
        if self._cache and 200 <= result.status < 300:
            self._cache.store(url, result.headers, result.content)
        return result

    async def _get_with_retries(self, url: str, headers: dict[str, str]) -> HttpResult:
        attempts = self.settings.http_max_retries + 1
        last_error: HttpFetchError | None = None
        for attempt in range(attempts):
            try:
                result = await self._get_following_redirects(url, headers)
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = HttpFetchError(f"network error: {type(exc).__name__}", url=url)
                delay = None
            else:
                if result.status not in self._retry_status:
                    if result.status >= 400:
                        raise HttpFetchError(_error_text(result), status=result.status, url=url)
                    return result
                err_cls = RateLimitedError if result.status == 429 else HttpFetchError
                last_error = err_cls(_error_text(result), status=result.status, url=url)
                delay = _retry_after_seconds(result.headers.get("retry-after"))
            if attempt + 1 >= attempts:
                break
            backoff = min(MAX_BACKOFF_SECONDS, (2**attempt) + random.uniform(0, 1))  # noqa: S311
            wait = min(MAX_RETRY_AFTER_SECONDS, delay) if delay is not None else backoff
            log.warning(
                "retrying request",
                extra={
                    "url": url,
                    "attempt": attempt + 1,
                    "wait_seconds": round(wait, 2),
                    "error": str(last_error),
                },
            )
            await self._sleep(wait)
        assert last_error is not None
        raise last_error

    async def _get_following_redirects(self, url: str, headers: dict[str, str]) -> HttpResult:
        current = url
        for _hop in range(self.settings.http_max_redirects + 1):
            check_url(current, self.allowed_hosts)
            if self.requests_made >= self._max_requests:
                raise RequestBudgetExceededError("per-run request budget exhausted", url=current)
            self.requests_made += 1
            await self._pace()
            async with self._client.stream("GET", current, headers=headers) as response:
                if response.status_code in REDIRECT_STATUS:
                    location = response.headers.get("location")
                    if not location:
                        raise HttpFetchError(
                            "redirect without Location header", response.status_code, current
                        )
                    current = urljoin(current, location)
                    continue
                body = await self._read_limited(response)
                return HttpResult(
                    url=current,
                    status=response.status_code,
                    content=body,
                    headers={k.lower(): v for k, v in response.headers.items()},
                )
        raise HttpFetchError("too many redirects", url=url)

    async def _pace(self) -> None:
        if self._min_interval <= 0:
            return
        loop = asyncio.get_running_loop()
        if self._last_request is not None:
            wait = self._last_request + self._min_interval - loop.time()
            if wait > 0:
                await self._sleep(wait)
        self._last_request = loop.time()

    async def _read_limited(self, response: httpx.Response) -> bytes:
        limit = self._max_bytes
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise ResponseTooLargeError(
                f"response exceeds {limit} bytes", response.status_code, str(response.url)
            )
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > limit:
                raise ResponseTooLargeError(
                    f"response exceeds {limit} bytes", response.status_code, str(response.url)
                )
            chunks.append(chunk)
        return b"".join(chunks)
