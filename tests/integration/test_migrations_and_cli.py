import json

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

from siren_threatwatch import cli
from siren_threatwatch.db.migrate import current_revision, upgrade_database
from siren_threatwatch.db.models import Base


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    upgrade_database(url)
    assert current_revision(url) == "0002"
    engine = create_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    engine.dispose()
    assert diff == []


def test_cli_seed_score_export(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SIREN_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("SIREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SIREN_LOG_LEVEL", "ERROR")
    cli.get_settings.cache_clear()
    from siren_threatwatch.db import base

    base._engine = None  # force a fresh engine for the env-configured DB
    try:
        assert cli.main(["init"]) == 0
        assert cli.main(["seed-demo"]) == 0
        assert cli.main(["score", "--explain", "CVE-2099-0001"]) == 0
        assert "source-reported" in capsys.readouterr().out
        assert cli.main(["export", "--format", "json", "--out", "-", "--days", "0"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["contains_synthetic_data"] is True
        assert any(v["cve_id"] == "CVE-2099-0001" for v in payload["vulnerabilities"])
        assert cli.main(["purge-demo"]) == 0
        assert cli.main(["dashboard", "--host", "0.0.0.0"]) == 2  # refuses non-localhost without opt-in
    finally:
        cli.get_settings.cache_clear()
        base._engine = None
