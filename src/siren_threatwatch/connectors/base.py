"""Connector framework and the source catalogue."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from siren_threatwatch.config import Settings
from siren_threatwatch.connectors.http import SafeHttpClient
from siren_threatwatch.normalization.schema import NormalizedRecord


class ConnectorError(RuntimeError):
    """A connector failed in a way that should mark the run as failed."""


@dataclass
class FetchResult:
    records: list[NormalizedRecord] = field(default_factory=list)
    rejected: int = 0
    rejection_samples: list[str] = field(default_factory=list)
    fetched_url: str | None = None
    http_status: int | None = None
    from_cache: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def reject(self, reason: str) -> None:
        self.rejected += 1
        if len(self.rejection_samples) < 10:
            self.rejection_samples.append(reason[:300])


class BaseConnector(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    allowed_hosts: ClassVar[frozenset[str]] = frozenset()
    credential_env: ClassVar[str | None] = None
    docs_url: ClassVar[str] = ""
    default_confidence: ClassVar[int | None] = None

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def configuration_status(self) -> tuple[bool, str]:
        """Return ``(ready, reason)``. Connectors needing credentials are disabled until configured."""
        return True, "ready"

    def make_client(self, **kwargs: Any) -> SafeHttpClient:
        return SafeHttpClient(self.settings, self.allowed_hosts, **kwargs)

    @abstractmethod
    async def fetch(self, client: SafeHttpClient) -> FetchResult:
        """Collect and normalise records. Must be passive and read-only."""


@dataclass(frozen=True)
class SourceSpec:
    name: str
    display_name: str
    phase: int
    implemented: bool
    requires_credential: str | None
    docs_url: str
    notes: str = ""


# The full planned catalogue — shown in Settings so users can see what is and is not implemented.
SOURCE_CATALOG: tuple[SourceSpec, ...] = (
    SourceSpec(
        "cisa_kev",
        "CISA Known Exploited Vulnerabilities",
        1,
        True,
        None,
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "Public JSON feed; falls back to CISA's official GitHub mirror (cisagov/kev-data).",
    ),
    SourceSpec(
        "nvd",
        "NVD CVE API 2.0",
        2,
        False,
        "NVD_API_KEY (optional)",
        "https://nvd.nist.gov/developers/vulnerabilities",
        "Planned: CVSS & affected products.",
    ),
    SourceSpec(
        "mitre_attack",
        "MITRE ATT&CK (STIX 2.1)",
        2,
        False,
        None,
        "https://github.com/mitre-attack/attack-stix-data",
        "Planned: actors, techniques, software.",
    ),
    SourceSpec(
        "urlhaus",
        "abuse.ch URLhaus",
        3,
        False,
        "ABUSECH_AUTH_KEY",
        "https://urlhaus-api.abuse.ch/",
        "Planned. Requires an abuse.ch Auth-Key.",
    ),
    SourceSpec(
        "threatfox",
        "abuse.ch ThreatFox",
        3,
        False,
        "ABUSECH_AUTH_KEY",
        "https://threatfox.abuse.ch/api/",
        "Planned. Requires an abuse.ch Auth-Key.",
    ),
    SourceSpec(
        "otx",
        "AlienVault OTX pulses",
        3,
        False,
        "OTX_API_KEY",
        "https://otx.alienvault.com/api",
        "Planned. Requires an OTX API key.",
    ),
    SourceSpec(
        "rss", "Curated security research RSS", 3, False, None, "", "Planned: configurable allowlist."
    ),
    SourceSpec(
        "synthetic_demo",
        "Synthetic demo dataset",
        1,
        True,
        None,
        "",
        "Local, clearly-labelled fake data for exploring the dashboard.",
    ),
)
