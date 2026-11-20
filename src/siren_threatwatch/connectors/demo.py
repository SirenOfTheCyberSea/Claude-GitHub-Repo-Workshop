"""Loads the bundled SYNTHETIC demo dataset through the normal normalisation pipeline."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any, ClassVar

from pydantic import ValidationError

from siren_threatwatch.connectors.base import BaseConnector, FetchResult
from siren_threatwatch.connectors.http import SafeHttpClient
from siren_threatwatch.normalization.schema import NormalizedRecord

DEMO_SOURCE = "synthetic_demo"


def load_dataset() -> dict[str, Any]:
    text = resources.files("siren_threatwatch.demo").joinpath("synthetic_dataset.json").read_text("utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def build_demo_records(now: datetime | None = None) -> FetchResult:
    now = now or datetime.now(UTC)
    result = FetchResult(fetched_url="bundled:synthetic_dataset.json", details={"synthetic": True})
    for raw in load_dataset()["records"]:
        item = json.loads(json.dumps(raw))  # deep copy
        offset = item.pop("published_offset_days", 0)
        published = now - timedelta(days=offset)
        vuln = item.get("vulnerability")
        if vuln:
            if (d := vuln.pop("kev_date_added_offset_days", None)) is not None:
                vuln["kev_date_added"] = (now - timedelta(days=d)).date()
            if (d := vuln.pop("kev_due_offset_days", None)) is not None:
                vuln["kev_due_date"] = (now - timedelta(days=d)).date()
        try:
            result.records.append(
                NormalizedRecord(
                    source=DEMO_SOURCE,
                    published_at=published,
                    observed_at=published,
                    raw_payload=raw,
                    is_synthetic=True,
                    **item,
                )
            )
        except (ValueError, ValidationError) as exc:
            result.reject(f"{raw.get('external_id')}: {str(exc).splitlines()[0]}")
    return result


class SyntheticDemoConnector(BaseConnector):
    name: ClassVar[str] = DEMO_SOURCE
    display_name: ClassVar[str] = "Synthetic demo dataset"

    async def fetch(self, client: SafeHttpClient) -> FetchResult:
        return build_demo_records()
