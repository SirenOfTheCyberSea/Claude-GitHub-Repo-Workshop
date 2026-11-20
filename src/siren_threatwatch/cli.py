"""Command-line interface: ``siren <command>``.

Commands: init, ingest, sources, seed-demo, purge-demo, score, alerts, export, schedule, dashboard.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from siren_threatwatch import __version__
from siren_threatwatch.config import Settings, get_settings
from siren_threatwatch.logging_config import configure_logging


def _bootstrap(settings: Settings) -> None:
    from siren_threatwatch.db.base import secure_mkdir

    secure_mkdir(settings.data_dir)


def cmd_init(settings: Settings, _args: argparse.Namespace | None = None, quiet: bool = False) -> int:
    from siren_threatwatch.db.base import create_db_engine
    from siren_threatwatch.db.migrate import current_revision, upgrade_database

    _bootstrap(settings)
    create_db_engine(settings.database_url, settings).dispose()  # creates file with secure perms
    upgrade_database(settings.database_url)
    if not quiet:
        print(
            f"Database ready at {settings.database_url} (schema revision {current_revision(settings.database_url)})"
        )
    return 0


def _print_summary(summary: object) -> None:
    d = summary.as_dict()  # type: ignore[attr-defined]
    line = (
        f"[{d['status'].upper():>8}] {d['source']}: fetched={d['fetched']} new={d['new']} "
        f"updated={d['updated']} unchanged={d['unchanged']} rejected={d['rejected']} alerts={d['alerts']}"
    )
    if d.get("fetched_url"):
        line += f"  via {d['fetched_url']}"
    print(line)
    if d.get("error"):
        print(f"           reason: {d['error']}")
    for note in d.get("notes") or []:
        print(f"           note: {note}")


def cmd_ingest(settings: Settings, args: argparse.Namespace) -> int:
    from siren_threatwatch.ingestion.pipeline import ingest_all, ingest_source

    cmd_init(settings, quiet=True)
    if args.source == "all":
        summaries = ingest_all(settings)
    else:
        file = Path(args.from_file) if args.from_file else None
        summaries = [
            ingest_source(
                args.source,
                settings,
                local_file=file,
                cve_ids=args.cve or None,
                recent_days=args.days,
                force=args.force,
            )
        ]
    for s in summaries:
        _print_summary(s)
    return 0 if all(s.status in ("success", "partial", "skipped") for s in summaries) else 1


def cmd_sources(settings: Settings, _args: argparse.Namespace) -> int:
    from siren_threatwatch import queries
    from siren_threatwatch.connectors import CONNECTORS, SOURCE_CATALOG
    from siren_threatwatch.db.base import session_scope

    cmd_init(settings, quiet=True)
    creds = settings.credential_status()
    print("\nConfigured sources:")
    for spec in SOURCE_CATALOG:
        if spec.implemented and spec.name in CONNECTORS:
            ready, reason = CONNECTORS[spec.name](settings).configuration_status()
            state = "READY" if ready else "DISABLED"
        else:
            ready, reason, state = False, f"planned for phase {spec.phase} — not implemented", "PLANNED"
        cred = ""
        if spec.requires_credential:
            env = spec.requires_credential.split()[0]
            cred = f" [credential {env}: {'configured' if creds.get(env) else 'not set'}]"
        print(f"  {state:<9} {spec.name:<15} {spec.display_name} — {reason}{cred}")
    with session_scope() as session:
        health = queries.source_health(session)
    print("\nSource health:")
    if health.empty:
        print("  No ingestion runs yet. Try:  siren ingest --source cisa_kev")
    for row in health.to_dict(orient="records"):
        print(
            f"  {row['source']:<15} last={row['last_status']:<9} at {row['last_run']:%Y-%m-%d %H:%M} UTC  "
            f"consecutive_failures={row['consecutive_failures']}  fetched={row['records_fetched']}"
        )
        if isinstance(row["last_error"], str) and row["last_error"]:
            print(f"      last error: {row['last_error']}")
    return 0


def cmd_seed_demo(settings: Settings, args: argparse.Namespace) -> int:
    from siren_threatwatch.ingestion.pipeline import ingest_source

    cmd_init(settings, quiet=True)
    summary = ingest_source("synthetic_demo", settings)
    _print_summary(summary)
    print("NOTE: demo records are SYNTHETIC and labelled as such. Remove with:  siren purge-demo")
    return 0 if summary.status in ("success", "partial") else 1


def cmd_purge_demo(settings: Settings, args: argparse.Namespace) -> int:
    from siren_threatwatch import queries
    from siren_threatwatch.db.base import session_scope

    cmd_init(settings, quiet=True)
    with session_scope() as session:
        removed = queries.purge_synthetic(session)
    print(f"Removed {removed} synthetic rows.")
    return 0


def cmd_score(settings: Settings, args: argparse.Namespace) -> int:
    from siren_threatwatch import queries
    from siren_threatwatch.db.base import session_scope
    from siren_threatwatch.db.models import VULNERABILITY
    from siren_threatwatch.prioritization.service import rescore_all

    cmd_init(settings, quiet=True)
    with session_scope() as session:
        results = rescore_all(session, settings)
        print(f"Rescored {len(results)} entities.")
        if args.explain:
            key = args.explain.strip().upper()
            res = results.get((VULNERABILITY, key))
            if res is None:
                print(f"No vulnerability {key} found.")
                return 1
            print(res.explain())
        else:
            df = queries.vulnerabilities_df(session, queries.VulnFilter(limit=args.top))
            for row in df.to_dict(orient="records"):
                print(
                    f"  {row['priority_score']:>5.1f} {row['priority_band']:<13} {row['cve_id']:<18} "
                    f"{(row['vendor'] or '')[:20]:<20} {(row['product'] or '')[:30]}"
                )
    return 0


def cmd_alerts(settings: Settings, args: argparse.Namespace) -> int:
    from siren_threatwatch import queries
    from siren_threatwatch.db.base import session_scope

    cmd_init(settings, quiet=True)
    with session_scope() as session:
        if args.ack:
            print(f"Acknowledged {queries.acknowledge_alerts(session, args.ack)} alert(s).")
            return 0
        df = queries.alerts_df(session, include_acknowledged=args.all)
    if df.empty:
        print("No open alerts.")
    for row in df.to_dict(orient="records"):
        print(
            f"  #{row['id']:<5} {row['created_at']:%Y-%m-%d %H:%M} {row['severity']:<8} {row['alert_type']:<18} "
            f"{row['title']}"
        )
    return 0


def cmd_export(settings: Settings, args: argparse.Namespace) -> int:
    from siren_threatwatch.db.base import session_scope
    from siren_threatwatch.reporting.builder import FORMATS, gather, render
    from siren_threatwatch.reporting.exporters import write_export

    cmd_init(settings, quiet=True)
    with session_scope() as session:
        data = gather(
            session,
            include_intel=args.include_intel,
            period_days=args.days,
            kev_only=args.kev_only,
            include_synthetic=not args.exclude_synthetic,
        )
        content = render(data, args.format)
    if args.out == "-":
        sys.stdout.write(content)
        return 0
    out = (
        Path(args.out)
        if args.out
        else (
            settings.export_dir
            / f"siren-{args.format}-{datetime.now(UTC):%Y%m%d-%H%M%S}{FORMATS[args.format]}"
        )
    )
    write_export(content, out)
    print(f"Wrote {out}")
    return 0


def cmd_schedule(settings: Settings, args: argparse.Namespace) -> int:
    from siren_threatwatch.ingestion.scheduler import run_scheduler

    cmd_init(settings, quiet=True)
    print(f"Ingesting every {settings.schedule_interval_minutes} minutes. Press Ctrl+C to stop.")
    run_scheduler(settings)
    return 0


def cmd_dashboard(settings: Settings, args: argparse.Namespace) -> int:
    cmd_init(settings, quiet=True)
    app = Path(__file__).resolve().parent / "dashboard" / "app.py"
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "WARNING: exposing the dashboard beyond localhost. It has NO built-in authentication. Put it behind "
            "an authenticating TLS reverse proxy first (see README, 'Network exposure').",
            file=sys.stderr,
        )
        if not args.i_understand_the_risk:
            print("Refusing. Re-run with --i-understand-the-risk to proceed.", file=sys.stderr)
            return 2
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app),
        "--server.address",
        args.host,
        "--server.port",
        str(args.port),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]
    print(f"Starting dashboard at http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        return subprocess.call(cmd, env=os.environ.copy())  # noqa: S603 - fixed argv, no shell
    except KeyboardInterrupt:
        return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="siren", description="Siren ThreatWatch — defensive CTI platform")
    p.add_argument("--version", action="version", version=f"siren-threatwatch {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create / migrate the local database").set_defaults(func=cmd_init)

    ing = sub.add_parser("ingest", help="collect intelligence from a source")
    ing.add_argument(
        "--source",
        default="cisa_kev",
        help="cisa_kev | nvd | mitre_attack | synthetic_demo | all (default: cisa_kev)",
    )
    ing.add_argument(
        "--from-file", help="offline import of a downloaded file (cisa_kev JSON or ATT&CK STIX bundle)"
    )
    ing.add_argument("--cve", nargs="+", metavar="CVE-ID", help="nvd: look up specific CVEs only")
    ing.add_argument(
        "--days", type=int, metavar="N", help="nvd: also pull CVEs modified in the last N days (≤120)"
    )
    ing.add_argument(
        "--force", action="store_true", help="mitre_attack: re-import even if the release is unchanged"
    )
    ing.set_defaults(func=cmd_ingest)

    sub.add_parser("sources", help="show configured sources, credential status and health").set_defaults(
        func=cmd_sources
    )
    sub.add_parser("seed-demo", help="load the SYNTHETIC demo dataset").set_defaults(func=cmd_seed_demo)
    sub.add_parser("purge-demo", help="remove all synthetic demo data").set_defaults(func=cmd_purge_demo)

    sc = sub.add_parser("score", help="recompute priorities; --explain CVE shows the factor breakdown")
    sc.add_argument("--explain", metavar="CVE-ID")
    sc.add_argument("--top", type=int, default=15)
    sc.set_defaults(func=cmd_score)

    al = sub.add_parser("alerts", help="list or acknowledge alerts")
    al.add_argument("--all", action="store_true", help="include acknowledged alerts")
    al.add_argument("--ack", type=int, nargs="+", metavar="ID", help="acknowledge alert IDs")
    al.set_defaults(func=cmd_alerts)

    ex = sub.add_parser("export", help="export a report")
    ex.add_argument(
        "--format", default="md-executive", choices=["md-executive", "md-technical", "json", "csv", "stix"]
    )
    ex.add_argument("--out", help="output path, or '-' for stdout (default: data/exports/...)")
    ex.add_argument("--days", type=int, default=30, help="reporting window in days (0 = all)")
    ex.add_argument("--kev-only", action="store_true")
    ex.add_argument("--exclude-synthetic", action="store_true")
    ex.add_argument(
        "--include-intel",
        action="store_true",
        help="json/stix: also export actors, campaigns, software, techniques and relationships",
    )
    ex.set_defaults(func=cmd_export)

    sub.add_parser("schedule", help="run recurring ingestion in the foreground").set_defaults(
        func=cmd_schedule
    )

    db = sub.add_parser("dashboard", help="launch the Streamlit dashboard (localhost only by default)")
    db.add_argument("--host", default="127.0.0.1")
    db.add_argument("--port", type=int, default=8501)
    db.add_argument("--i-understand-the-risk", action="store_true", help=argparse.SUPPRESS)
    db.set_defaults(func=cmd_dashboard)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(
        "DEBUG" if args.verbose else settings.log_level, settings.log_json, settings.secret_values()
    )
    return int(args.func(settings, args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
