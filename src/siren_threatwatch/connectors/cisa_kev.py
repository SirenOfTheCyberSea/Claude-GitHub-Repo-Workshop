"""CISA Known Exploited Vulnerabilities connector (no credentials required)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from pydantic import ValidationError

from siren_threatwatch.config import Settings
from siren_threatwatch.connectors.base import BaseConnector, ConnectorError, FetchResult
from siren_threatwatch.connectors.http import HttpFetchError, HttpResult, SafeHttpClient
from siren_threatwatch.normalization.kev import KEV_CONFIDENCE, KEV_SOURCE, KevCatalog, normalize_kev_entry

log = logging.getLogger(__name__)
MAX_KEV_ENTRIES = 50_000  # sanity bound on untrusted input


def parse_catalog(payload: Any, result: FetchResult) -> FetchResult:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ConnectorError("KEV payload does not match the expected schema (no 'vulnerabilities' list)")
    try:
        catalog = KevCatalog.model_validate(payload)
    except ValidationError as exc:
        raise ConnectorError(f"KEV envelope failed validation: {exc.error_count()} error(s)") from exc
    if len(catalog.vulnerabilities) > MAX_KEV_ENTRIES:
        raise ConnectorError("KEV payload unexpectedly large; refusing to process")
    result.details.update(
        catalog_version=catalog.catalogVersion,
        date_released=catalog.dateReleased.isoformat() if catalog.dateReleased else None,
        declared_count=catalog.count,
    )
    seen: set[str] = set()
    for item in catalog.vulnerabilities:
        try:
            record = normalize_kev_entry(item, catalog.dateReleased)
        except (ValueError, ValidationError) as exc:
            cve = item.get("cveID") if isinstance(item, dict) else None
            result.reject(f"{cve or '<no cveID>'}: {str(exc).splitlines()[0]}")
            continue
        if record.entity_key in seen:  # duplicate entries inside a single feed
            continue
        seen.add(record.entity_key)
        result.records.append(record)
    return result


class CisaKevConnector(BaseConnector):
    name: ClassVar[str] = KEV_SOURCE
    display_name: ClassVar[str] = "CISA Known Exploited Vulnerabilities"
    allowed_hosts: ClassVar[frozenset[str]] = frozenset({"www.cisa.gov", "raw.githubusercontent.com"})
    docs_url: ClassVar[str] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    default_confidence: ClassVar[int | None] = KEV_CONFIDENCE

    def __init__(self, settings: Settings, local_file: Path | None = None) -> None:
        super().__init__(settings)
        self.local_file = local_file

    def configuration_status(self) -> tuple[bool, str]:
        if not self.settings.kev_enabled:
            return False, "disabled via SIREN_KEV_ENABLED=false"
        return True, "ready (no API key required)"

    async def fetch(self, client: SafeHttpClient) -> FetchResult:
        result = FetchResult()
        if self.local_file is not None:
            # Offline / air-gapped import of a manually downloaded KEV JSON file.
            result.fetched_url = f"file:{self.local_file.name}"
            result.details["offline_import"] = True
            try:
                payload = json.loads(self.local_file.read_text("utf-8"))
            except (OSError, ValueError) as exc:
                raise ConnectorError(f"could not read local KEV file: {exc}") from exc
            return parse_catalog(payload, result)

        response: HttpResult | None = None
        errors: list[str] = []
        for label, url in (("primary", self.settings.kev_feed_url), ("mirror", self.settings.kev_mirror_url)):
            try:
                response = await client.get(url)
                result.details["endpoint"] = label
                break
            except HttpFetchError as exc:
                errors.append(f"{label}: {exc}")
                log.warning("KEV endpoint failed", extra={"endpoint": label, "error": str(exc)})
        if response is None:
            raise ConnectorError("all KEV endpoints failed — " + "; ".join(errors))
        if errors:
            result.details["endpoint_errors"] = errors
        result.fetched_url = response.url
        result.http_status = response.status
        result.from_cache = response.from_cache
        try:
            payload = response.json()
        except ValueError as exc:
            raise ConnectorError("KEV response is not valid JSON") from exc
        return parse_catalog(payload, result)
