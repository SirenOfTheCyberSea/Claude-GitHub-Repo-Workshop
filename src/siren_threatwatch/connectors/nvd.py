"""NVD CVE API 2.0 connector (API key optional).

What it does, in order (each step is passive and paginated):

1. ``hasKev`` — every CVE in CISA KEV with NVD's CVSS, CWE and CPE data (one page of up to 2000 today).
2. Optional ``lastModStartDate``/``lastModEndDate`` window(s) over the last ``SIREN_NVD_RECENT_DAYS`` days.
3. Single ``cveId`` lookups for other tracked CVEs (e.g. watchlist) not yet enriched, capped.

Verified against the live API in this project: ``resultsPerPage`` max 2000; date ranges max 120 days and
start+end required together; ``hasKev`` and ``noRejected`` are value-less flags; errors are HTTP 404 with a
``message`` header; unknown CVE IDs return 200 with ``totalResults: 0``.

Not re-verifiable from the build environment (the docs site rejected automated fetches): the documented
rate limits and the ``apiKey`` request header. Pacing is therefore conservative and configurable
(``SIREN_NVD_REQUEST_INTERVAL_SECONDS``), and HTTP 403/429/5xx are retried with backoff.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from pydantic import ValidationError

from siren_threatwatch.config import Settings
from siren_threatwatch.connectors.base import BaseConnector, ConnectorError, FetchResult
from siren_threatwatch.connectors.http import HttpFetchError, SafeHttpClient
from siren_threatwatch.normalization.nvd import NVD_SOURCE, normalize_nvd_item
from siren_threatwatch.normalization.schema import NormalizedRecord, canonical_cve

log = logging.getLogger(__name__)
PAGE_SIZE = 2000  # server maximum (verified)
MAX_WINDOW_DAYS = 120  # server maximum (verified)


def _nvd_date(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def date_windows(
    start: datetime, end: datetime, max_days: int = MAX_WINDOW_DAYS
) -> list[tuple[datetime, datetime]]:
    windows = []
    cursor = start
    while cursor < end:
        nxt = min(cursor + timedelta(days=max_days), end)
        windows.append((cursor, nxt))
        cursor = nxt
    return windows


class NvdConnector(BaseConnector):
    name: ClassVar[str] = NVD_SOURCE
    display_name: ClassVar[str] = "NVD CVE API 2.0"
    allowed_hosts: ClassVar[frozenset[str]] = frozenset({"services.nvd.nist.gov"})
    credential_env: ClassVar[str | None] = "NVD_API_KEY"
    docs_url: ClassVar[str] = "https://nvd.nist.gov/developers/vulnerabilities"

    def __init__(
        self,
        settings: Settings,
        *,
        cve_ids: list[str] | None = None,
        recent_days: int | None = None,
        tracked_cves: list[str] | None = None,
        include_kev: bool = True,
    ) -> None:
        super().__init__(settings)
        self.cve_ids = [canonical_cve(c) for c in cve_ids or []]
        self.recent_days = settings.nvd_recent_days if recent_days is None else recent_days
        self.tracked_cves = [canonical_cve(c) for c in tracked_cves or []]
        self.include_kev = include_kev and not self.cve_ids

    def configuration_status(self) -> tuple[bool, str]:
        if not self.settings.nvd_enabled:
            return False, "disabled via SIREN_NVD_ENABLED=false"
        key = "API key configured" if self.settings.nvd_api_key else "no API key (slower public rate)"
        return True, f"ready — {key}; ≥{self.settings.nvd_interval:g}s between requests"

    def make_client(self, **kwargs: Any) -> SafeHttpClient:
        kwargs.setdefault("min_interval", self.settings.nvd_interval)
        kwargs.setdefault("use_cache", False)  # query responses are time-windowed; caching adds no value
        kwargs.setdefault("extra_retry_status", {403})
        kwargs.setdefault(
            "max_requests", self.settings.nvd_max_pages * 4 + self.settings.nvd_lookup_limit + 10
        )
        return SafeHttpClient(self.settings, self.allowed_hosts, **kwargs)

    def _headers(self) -> dict[str, str]:
        key = self.settings.nvd_api_key
        return {"apiKey": key.get_secret_value()} if key else {}

    async def _paged(
        self,
        client: SafeHttpClient,
        query: str,
        step: str,
        result: FetchResult,
        found: dict[str, tuple[datetime | None, NormalizedRecord]],
    ) -> None:
        start, pages = 0, 0
        while True:
            if pages >= self.settings.nvd_max_pages:
                result.details.setdefault("truncated_steps", []).append(step)
                log.warning("NVD page cap reached", extra={"step": step, "pages": pages})
                return
            url = f"{self.settings.nvd_api_url}?{query}&resultsPerPage={PAGE_SIZE}&startIndex={start}"
            response = await client.get(url, headers=self._headers())
            pages += 1
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise ConnectorError(f"NVD response for {step} does not match the expected schema")
            for item in payload["vulnerabilities"]:
                self._accept(item, result, found)
            total = int(payload.get("totalResults") or 0)
            per_page = int(payload.get("resultsPerPage") or 0)
            result.details.setdefault("steps", {})[step] = {"total_results": total, "pages": pages}
            start += per_page
            if per_page <= 0 or start >= total:
                return

    @staticmethod
    def _accept(
        item: Any, result: FetchResult, found: dict[str, tuple[datetime | None, NormalizedRecord]]
    ) -> None:
        try:
            rec = normalize_nvd_item(item)
        except (ValueError, ValidationError) as exc:
            cve = item.get("cve", {}).get("id") if isinstance(item, dict) else None
            result.reject(f"{cve or '<no id>'}: {str(exc).splitlines()[0]}")
            return
        modified = rec.observed_at
        prev = found.get(rec.entity_key)
        if prev is None or (modified and (prev[0] is None or modified > prev[0])):
            found[rec.entity_key] = (modified, rec)

    async def fetch(self, client: SafeHttpClient) -> FetchResult:
        result = FetchResult(fetched_url=self.settings.nvd_api_url)
        result.details["api_key_configured"] = self.settings.nvd_api_key is not None
        found: dict[str, tuple[datetime | None, NormalizedRecord]] = {}
        errors: list[str] = []

        async def step(name: str, coro: Any) -> None:
            try:
                await coro
            except HttpFetchError as exc:
                errors.append(f"{name}: {exc}")
                log.warning("NVD step failed", extra={"step": name, "error": str(exc)})

        if self.include_kev:
            await step("hasKev", self._paged(client, "hasKev&noRejected", "hasKev", result, found))
        if self.recent_days and not self.cve_ids:
            end = datetime.now(UTC)
            for i, (a, b) in enumerate(date_windows(end - timedelta(days=self.recent_days), end)):
                q = f"noRejected&lastModStartDate={_nvd_date(a)}&lastModEndDate={_nvd_date(b)}"
                await step(f"lastMod[{i}]", self._paged(client, q, f"lastMod[{i}]", result, found))
        lookups = (
            self.cve_ids or [c for c in self.tracked_cves if c not in found][: self.settings.nvd_lookup_limit]
        )
        not_found = []
        for cve in lookups:
            before = len(found)
            await step(f"cveId:{cve}", self._paged(client, f"cveId={cve}", f"cveId:{cve}", result, found))
            if len(found) == before and cve not in found:
                not_found.append(cve)

        result.records = [rec for _, rec in found.values()]
        result.details.update(requests=client.requests_made, lookups=len(lookups), not_found=not_found[:50])
        if errors:
            result.details["step_errors"] = errors[:20]
            if not result.records:
                raise ConnectorError("all NVD requests failed — " + "; ".join(errors[:3]))
            result.details["partial"] = True
        return result
