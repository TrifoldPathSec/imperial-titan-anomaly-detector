"""Flask dashboard: devices, their learned baselines, and alerts.

It reads the same SQLite file the sensor writes (WAL mode makes that safe).
"Now" is the newest packet in the database rather than the wall clock, so a
replayed pcap or the demo looks the way it did live.
"""

from __future__ import annotations

import sqlite3
import time
from urllib.parse import urlparse

from flask import Flask, abort, g, redirect, render_template, request, url_for

from . import db
from .config import Config
from .engine import display_name

KINDS = {
    "new_device": "New device",
    "new_dns": "New domain",
    "unusual_hour": "Unusual hour",
    "volume_spike": "Volume spike",
    "lan_scan": "LAN scan",
}


def create_app(cfg: Config) -> Flask:
    app = Flask(__name__)
    app.config["TITAN"] = cfg

    def conn() -> sqlite3.Connection:
        if "db" not in g:
            g.db = db.connect(cfg.db_path)
        return g.db

    @app.teardown_appcontext
    def _close(_exc):
        c = g.pop("db", None)
        if c is not None:
            c.close()

    @app.before_request
    def _same_origin_posts():
        # No login, so at least refuse POSTs that another website triggers.
        if request.method == "POST":
            source = request.headers.get("Origin") or request.headers.get("Referer") or ""
            if urlparse(source).netloc != request.host:
                abort(403)

    def ref_now() -> float:
        last = db.get_meta(conn(), "last_ts")
        return float(last) if last and float(last) > 0 else time.time()

    @app.template_filter("when")
    def _when(ts):
        return time.strftime("%b %d %H:%M", time.localtime(ts)) if ts else "–"

    @app.template_filter("ago")
    def _ago(ts):
        if not ts:
            return "–"
        s = max(0, ref_now() - ts)
        for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
            if s >= n:
                return f"{int(s // n)}{unit} ago"
        return "just now"

    @app.template_filter("bytes")
    def _bytes(n):
        n = float(n or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1000:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1000
        return f"{n:.1f} TB"

    @app.context_processor
    def _globals():
        return {"KINDS": KINDS, "name": lambda d: display_name(dict(d))}

    def learning_state() -> dict:
        start = db.get_meta(conn(), "sensor_start")
        if not start:
            return {"started": False}
        start, now = float(start), ref_now()
        total = cfg.learning_hours * 3600
        pct = min(100, int((now - start) / total * 100)) if total else 100
        return {"started": True, "pct": pct, "done": pct >= 100, "ends": start + total, "start": start}

    @app.route("/")
    def index():
        c, now = conn(), ref_now()
        devices = c.execute(
            """SELECT d.*,
                 (SELECT COUNT(*) FROM device_domains x WHERE x.mac = d.mac) AS domains,
                 (SELECT COUNT(*) FROM alerts a WHERE a.mac = d.mac AND a.acked = 0) AS open_alerts
               FROM devices d ORDER BY d.last_seen DESC"""
        ).fetchall()
        alerts = c.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 12").fetchall()
        tiles = {
            "devices": len(devices),
            "active": sum(1 for d in devices if d["last_seen"] >= now - 3600),
            "open": c.execute("SELECT COUNT(*) FROM alerts WHERE acked = 0").fetchone()[0],
            "day": c.execute("SELECT COUNT(*) FROM alerts WHERE ts >= ?", (now - 86400,)).fetchone()[0],
            "domains": c.execute("SELECT COUNT(DISTINCT domain) FROM device_domains").fetchone()[0],
        }
        return render_template("index.html", devices=devices, alerts=alerts, tiles=tiles,
                               learning=learning_state(), now=now)

    @app.route("/device/<mac>")
    def device(mac):
        c, now = conn(), ref_now()
        dev = c.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        if dev is None:
            abort(404)
        rows = c.execute(
            "SELECT day, hour, packets, ext_packets, ext_bytes FROM activity WHERE mac = ?", (mac,)
        ).fetchall()
        days = sorted({r["day"] for r in rows if r["packets"] > 0})
        floor = max(1, cfg.rare_hour_min_packets // 2)
        hours = []
        for h in range(24):
            hr = [r for r in rows if r["hour"] == h]
            active = sum(1 for r in hr if r["ext_packets"] >= floor)
            pk = sum(r["ext_packets"] for r in hr)
            hours.append({"hour": h, "active": active, "avg": pk / len(days) if days else 0,
                          "rare": bool(days) and active / len(days) < cfg.rare_hour_ratio})
        peak = max((h["avg"] for h in hours), default=0) or 1
        domains = c.execute(
            "SELECT * FROM device_domains WHERE mac = ? ORDER BY first_seen DESC", (mac,)
        ).fetchall()
        dests = c.execute(
            "SELECT * FROM destinations WHERE mac = ? ORDER BY bytes DESC LIMIT 25", (mac,)
        ).fetchall()
        alerts = c.execute("SELECT * FROM alerts WHERE mac = ? ORDER BY ts DESC", (mac,)).fetchall()
        return render_template("device.html", dev=dev, hours=hours, peak=peak, ndays=len(days),
                               domains=domains, dests=dests, alerts=alerts, now=now,
                               grace=dev["first_seen"] + cfg.device_grace_hours * 3600)

    @app.post("/device/<mac>/label")
    def label(mac):
        text = (request.form.get("label") or "").strip()[:60] or None
        c = conn()
        c.execute("UPDATE devices SET label = ? WHERE mac = ?", (text, mac))
        c.commit()
        return redirect(url_for("device", mac=mac))

    @app.route("/alerts")
    def alerts():
        kind = request.args.get("kind", "")
        severity = request.args.get("severity", "")
        status = request.args.get("status", "open")
        where, params = [], []
        if kind in KINDS:
            where.append("kind = ?")
            params.append(kind)
        if severity in ("low", "medium", "high"):
            where.append("severity = ?")
            params.append(severity)
        if status == "open":
            where.append("acked = 0")
        sql = "SELECT a.*, d.label, d.hostname, d.vendor FROM alerts a LEFT JOIN devices d ON d.mac = a.mac"
        if where:
            sql += " WHERE " + " AND ".join(where)
        rows = conn().execute(sql + " ORDER BY a.ts DESC LIMIT 500", params).fetchall()
        return render_template("alerts.html", rows=rows, kind=kind, severity=severity, status=status)

    @app.post("/alerts/ack")
    def ack():
        ids = [int(i) for i in request.form.getlist("id") if i.isdigit()]
        c = conn()
        if ids:
            c.executemany("UPDATE alerts SET acked = 1 WHERE id = ?", [(i,) for i in ids])
            c.commit()
        nxt = request.form.get("next") or ""
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = url_for("alerts")  # local paths only: no open redirect
        return redirect(nxt)

    @app.route("/api/alerts")
    def api_alerts():
        rows = conn().execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 200").fetchall()
        return {"alerts": [dict(r) for r in rows]}

    @app.route("/api/devices")
    def api_devices():
        rows = conn().execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return {"devices": [dict(r) for r in rows]}

    return app
