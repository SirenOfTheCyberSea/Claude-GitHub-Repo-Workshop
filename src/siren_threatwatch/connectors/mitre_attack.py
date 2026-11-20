"""MITRE ATT&CK connector — official STIX 2.1 data from github.com/mitre-attack/attack-stix-data.

The collection index (``index.json``) lists each domain's releases; the connector downloads the newest
release bundle per configured domain, and skips domains whose release version has not changed since the
last successful sync. A locally downloaded bundle can be imported with ``--from-file`` (read-only use).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from siren_threatwatch.config import Settings
from siren_threatwatch.connectors.base import BaseConnector, ConnectorError, FetchResult
from siren_threatwatch.connectors.http import HttpFetchError, SafeHttpClient
from siren_threatwatch.normalization.attack import ATTACK_SOURCE, parse_bundle

log = logging.getLogger(__name__)
DOMAIN_COLLECTIONS = {
    "enterprise-attack": "Enterprise ATT&CK",
    "mobile-attack": "Mobile ATT&CK",
    "ics-attack": "ICS ATT&CK",
}


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in str(version).split("."))
    except ValueError:
        return (0,)


def latest_release(index: Any, domain: str) -> tuple[str, str]:
    """Return ``(version, url)`` of the newest release of ``domain`` listed in the collection index."""
    if not isinstance(index, dict) or not isinstance(index.get("collections"), list):
        raise ConnectorError("ATT&CK collection index does not match the expected schema")
    name = DOMAIN_COLLECTIONS[domain]
    for coll in index["collections"]:
        if isinstance(coll, dict) and coll.get("name") == name:
            versions = [v for v in coll.get("versions") or [] if isinstance(v, dict) and v.get("url")]
            if not versions:
                break
            newest = max(versions, key=lambda v: _version_key(v.get("version", "0")))
            return str(newest.get("version")), str(newest["url"])
    raise ConnectorError(f"collection {name!r} not found in ATT&CK index")


class MitreAttackConnector(BaseConnector):
    name: ClassVar[str] = ATTACK_SOURCE
    display_name: ClassVar[str] = "MITRE ATT&CK (STIX 2.1)"
    allowed_hosts: ClassVar[frozenset[str]] = frozenset({"raw.githubusercontent.com"})
    docs_url: ClassVar[str] = "https://github.com/mitre-attack/attack-stix-data"

    def __init__(
        self,
        settings: Settings,
        *,
        local_file: Path | None = None,
        known_versions: dict[str, str] | None = None,
        force: bool = False,
    ) -> None:
        super().__init__(settings)
        self.local_file = local_file
        self.known_versions = known_versions or {}
        self.force = force

    def configuration_status(self) -> tuple[bool, str]:
        if not self.settings.mitre_enabled:
            return False, "disabled via SIREN_MITRE_ENABLED=false"
        return True, f"ready (no API key required) — domains: {', '.join(self.settings.mitre_domains)}"

    def make_client(self, **kwargs: Any) -> SafeHttpClient:
        kwargs.setdefault("max_bytes", self.settings.mitre_max_response_mb * 1024 * 1024)
        return SafeHttpClient(self.settings, self.allowed_hosts, **kwargs)

    async def fetch(self, client: SafeHttpClient) -> FetchResult:
        result = FetchResult()
        seen: set[str] = set()
        if self.local_file is not None:
            try:
                bundle = json.loads(self.local_file.read_text("utf-8"))
            except (OSError, ValueError) as exc:
                raise ConnectorError(f"could not read local ATT&CK bundle: {exc}") from exc
            result.fetched_url = f"file:{self.local_file.name}"
            self._absorb(bundle, "local", result, seen)
            return result

        try:
            index = (await client.get(self.settings.mitre_index_url)).json()
        except (HttpFetchError, ValueError) as exc:
            raise ConnectorError(f"could not load ATT&CK collection index: {exc}") from exc
        result.fetched_url = self.settings.mitre_index_url
        versions: dict[str, str] = {}
        for domain in self.settings.mitre_domains:
            version, url = latest_release(index, domain)
            versions[domain] = version
            if not self.force and self.known_versions.get(domain) == version:
                result.details.setdefault("unchanged_domains", []).append(f"{domain} v{version}")
                log.info(
                    "ATT&CK release unchanged; skipping download",
                    extra={"domain": domain, "version": version},
                )
                continue
            try:
                response = await client.get(url)
                bundle = response.json()
            except (HttpFetchError, ValueError) as exc:
                raise ConnectorError(f"could not download {domain} v{version}: {exc}") from exc
            result.http_status = response.status
            result.from_cache = result.from_cache or response.from_cache
            self._absorb(bundle, f"{domain} v{version}", result, seen)
        result.details["versions"] = versions
        return result

    @staticmethod
    def _absorb(bundle: Any, label: str, result: FetchResult, seen: set[str]) -> None:
        try:
            parsed = parse_bundle(bundle, seen)
        except ValueError as exc:
            raise ConnectorError(f"{label}: {exc}") from exc
        result.records.extend(parsed.records)
        for reason in parsed.rejected:
            result.reject(reason)
        result.details.setdefault("domains", {})[label] = {
            "objects": len(parsed.records),
            "relationships": parsed.relationships,
            "cve_mentions": parsed.cve_mentions,
            "skipped_revoked_or_deprecated": parsed.skipped_inactive,
            "attack_version": parsed.attack_version,
        }
