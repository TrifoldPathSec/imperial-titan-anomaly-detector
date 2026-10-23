"""Command line: python -m titan <command>."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import db
from .config import PROJECT_ROOT, Config, ensure_env_file
from .engine import Engine, fmt_time
from .notify import Notifier

DEMO_PCAP = PROJECT_ROOT / "samples" / "demo.pcap"
DEMO_DB = PROJECT_ROOT / "samples" / "demo.db"


def _engine(cfg: Config, push: bool) -> tuple[Engine, Notifier]:
    notifier = Notifier(cfg, enabled=push)
    return Engine(db.connect(cfg.db_path), cfg, notifier), notifier


def cmd_init(cfg: Config, args) -> None:
    path, created = ensure_env_file()
    cfg = Config.from_env()
    db.connect(cfg.db_path).close()
    print(f"database: {cfg.db_path}")
    if created:
        print(f"created {path} with a random ntfy topic")
    print(f"ntfy topic: {cfg.ntfy_topic}")
    print(f"  1. install the ntfy app (iOS / Android) and subscribe to that topic on {cfg.ntfy_server}")
    print("  2. run: python -m titan notify-test")


def cmd_capture(cfg: Config, args) -> None:
    from .capture import live

    engine, notifier = _engine(cfg, push=not args.no_push)
    if engine.network_learning(time.time()):
        print(f"[titan] learning mode: baseline alerts start {cfg.learning_hours:g}h after the first packet",
              file=sys.stderr)
    if not notifier.enabled and not args.no_push:
        print("[titan] NTFY_TOPIC not set: alerts go to the dashboard only", file=sys.stderr)
    try:
        live(engine, args.iface, args.filter, args.promisc)
    except KeyboardInterrupt:
        pass
    finally:
        engine.flush()
        notifier.close()


def cmd_ingest(cfg: Config, args) -> None:
    from .capture import ingest

    engine, notifier = _engine(cfg, push=args.push)
    ingest(engine, args.pcaps)
    notifier.close()


def cmd_dashboard(cfg: Config, args) -> None:
    from .dashboard import create_app

    host = args.host or cfg.dashboard_host
    port = args.port or cfg.dashboard_port
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[titan] WARNING: the dashboard has no login; anyone who can reach {host}:{port} can see it.",
              file=sys.stderr)
    create_app(cfg).run(host=host, port=port, debug=False)


def cmd_notify_test(cfg: Config, args) -> None:
    Notifier(cfg).send_test()
    print(f"sent a test push to {cfg.ntfy_server}/{cfg.ntfy_topic}")


def cmd_status(cfg: Config, args) -> None:
    conn = db.connect(cfg.db_path)
    start = db.get_meta(conn, "sensor_start")
    last = float(db.get_meta(conn, "last_ts", "0") or 0)
    if not start:
        print("no traffic recorded yet")
        return
    start = float(start)
    learn_end = start + cfg.learning_hours * 3600
    print(f"database:     {cfg.db_path}")
    print(f"first packet: {fmt_time(start)}")
    print(f"last packet:  {fmt_time(last)}")
    print(f"learning:     {'until ' + fmt_time(learn_end) if last < learn_end else 'complete'}")
    for table in ("devices", "device_domains", "destinations", "alerts"):
        print(f"{table + ':':14}{conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]:,}")
    for r in conn.execute("SELECT ts, severity, title FROM alerts ORDER BY ts DESC LIMIT 10"):
        print(f"  {fmt_time(r['ts'])}  {r['severity']:<6}  {r['title']}")


def cmd_demo(cfg: Config, args) -> None:
    from .capture import ingest
    from .synth import build

    DEMO_PCAP.parent.mkdir(exist_ok=True)
    for p in (DEMO_DB, Path(f"{DEMO_DB}-wal"), Path(f"{DEMO_DB}-shm")):
        p.unlink(missing_ok=True)
    n = build(str(DEMO_PCAP))
    print(f"wrote {n:,} synthetic packets to {DEMO_PCAP}")
    demo_cfg = cfg.with_overrides(db_path=DEMO_DB, spike_min_bytes=1_000_000)
    engine, notifier = _engine(demo_cfg, push=args.push)
    ingest(engine, [str(DEMO_PCAP)])
    notifier.close()
    cmd_status(demo_cfg, args)
    print(f"\nview it: python -m titan --db {DEMO_DB} dashboard")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="titan", description="Home network anomaly detector")
    p.add_argument("--db", help="SQLite database (default: data/titan.db or $TITAN_DB)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database and a .env with a private ntfy topic")

    c = sub.add_parser("capture", help="sniff live traffic (needs sudo)")
    c.add_argument("-i", "--iface", help="interface, e.g. en0 (default: Scapy's choice)")
    c.add_argument("-f", "--filter", help="BPF filter, e.g. 'not port 22'")
    c.add_argument("--no-push", action="store_true", help="don't send phone notifications")
    c.add_argument("--promisc", action="store_true",
                   help="promiscuous mode, for a wired mirror/SPAN port (not supported on macOS Wi-Fi)")

    i = sub.add_parser("ingest", help="read pcap/pcapng files into the baseline")
    i.add_argument("pcaps", nargs="+")
    i.add_argument("--push", action="store_true", help="send phone notifications for alerts")

    d = sub.add_parser("dashboard", help="run the Flask dashboard")
    d.add_argument("--host")
    d.add_argument("--port", type=int)

    sub.add_parser("notify-test", help="send one test push to your phone")
    sub.add_parser("status", help="learning progress, table sizes and recent alerts")

    dm = sub.add_parser("demo", help="generate a synthetic week of traffic and analyse it")
    dm.add_argument("--push", action="store_true", help="also push the demo alerts to your phone")

    args = p.parse_args(argv)
    cfg = Config.from_env()
    if args.db:
        cfg = cfg.with_overrides(db_path=Path(args.db).expanduser())
    {
        "init": cmd_init, "capture": cmd_capture, "ingest": cmd_ingest,
        "dashboard": cmd_dashboard, "notify-test": cmd_notify_test,
        "status": cmd_status, "demo": cmd_demo,
    }[args.cmd](cfg, args)
