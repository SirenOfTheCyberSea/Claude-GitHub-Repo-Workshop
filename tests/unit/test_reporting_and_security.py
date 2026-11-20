import csv
import io
import logging
import re

import pandas as pd
import pytest
from pydantic import ValidationError

from siren_threatwatch.config import Settings
from siren_threatwatch.dashboard.components import esc, link
from siren_threatwatch.logging_config import RedactingFilter
from siren_threatwatch.reporting.exporters import md_escape, sanitize_csv_cell, to_csv, to_stix_bundle


@pytest.mark.parametrize("cell", ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=x", "\r=x", "|calc"])
def test_csv_formula_injection_neutralised(cell):
    assert sanitize_csv_cell(cell).startswith("'")


def test_csv_safe_values_untouched_and_written():
    out = to_csv([{"a": '=HYPERLINK("http://x")', "b": "normal", "c": ["x", "y"], "d": 5}])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert rows[0]["a"].startswith("'=")
    assert rows[0]["b"] == "normal" and rows[0]["c"] == "x; y" and rows[0]["d"] == "5"


def test_markdown_escape_blocks_links_images_html():
    escaped = md_escape("![x](https://tracker.example/p.png) [click](javascript:x) <img src=x> :red[a]\nnext")
    assert "![" not in escaped and "](" not in escaped.replace("\\]", "")
    assert not re.search(r"(?<!\\)[<\[!]", escaped)  # every <, [ and ! is backslash-escaped
    assert "\n" not in escaped


def test_html_escape_and_link_safety():
    assert esc('<script>alert("x")</script>') == "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
    assert "<a" not in link("javascript:alert(1)")
    good = link("https://vendor.example/advisory?a=1&b=<2>")
    assert 'rel="noopener noreferrer nofollow"' in good or "<a" not in good


def test_stix_bundle_shape():
    vulns = pd.DataFrame(
        [
            {
                "cve_id": "CVE-2024-0001",
                "description": "d",
                "title": "t",
                "references": ["https://example.com"],
                "kev_listed": True,
                "is_synthetic": False,
                "first_seen_at": None,
            }
        ]
    )
    iocs = pd.DataFrame(
        [
            {
                "entity_key": "domain:evil.example",
                "ioc_type": "domain",
                "value": "evil.example",
                "description": "x",
                "confidence": 70,
                "tlp": "TLP:GREEN",
                "first_seen_at": None,
                "is_synthetic": True,
            },
            {
                "entity_key": "domain:it's.example",
                "ioc_type": "domain",
                "value": "it's.example",
                "description": None,
                "confidence": None,
                "tlp": None,
                "first_seen_at": None,
                "is_synthetic": False,
            },
        ]
    )
    bundle = to_stix_bundle(vulns, iocs)
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("vulnerability") == 1 and types.count("indicator") == 2
    for o in bundle["objects"]:
        assert o["spec_version"] == "2.1"
        assert re.match(r"^[a-z-]+--[0-9a-f-]{36}$", o["id"])
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[domain-name:value = 'evil.example']"
    assert ind["object_marking_refs"][0].startswith("marking-definition--")
    quoted = [o for o in bundle["objects"] if o["type"] == "indicator"][1]
    assert "\\'" in quoted["pattern"]
    vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
    assert vuln["external_references"][0] == {"source_name": "cve", "external_id": "CVE-2024-0001"}


def test_redaction_filter_masks_secrets():
    f = RedactingFilter(["supersecretvalue123"])
    rec = logging.makeLogRecord({"msg": "calling api_key=abcd1234 with supersecretvalue123", "args": ()})
    rec.api_key = "abc"
    f.filter(rec)
    assert "supersecretvalue123" not in rec.msg and "abcd1234" not in rec.msg
    assert rec.api_key == "***REDACTED***"


def test_settings_reject_non_allowlisted_feed_url(tmp_path):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, kev_feed_url="https://attacker.example/kev.json", data_dir=tmp_path)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, kev_feed_url="http://www.cisa.gov/x.json", data_dir=tmp_path)


def test_secrets_not_in_repr(tmp_path, monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "otx-secret-value")
    s = Settings(_env_file=None, data_dir=tmp_path)
    assert "otx-secret-value" not in repr(s)
    assert s.credential_status()["OTX_API_KEY"] is True
    monkeypatch.setenv("OTX_API_KEY", "  ")
    assert Settings(_env_file=None, data_dir=tmp_path).credential_status()["OTX_API_KEY"] is False


def test_keywords_parsed_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIREN_ORG_RELEVANT_KEYWORDS", "Fortinet, Ivanti ,,")
    assert Settings(_env_file=None, data_dir=tmp_path).org_relevant_keywords == ["fortinet", "ivanti"]
