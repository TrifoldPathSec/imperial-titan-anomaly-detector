"""The detection engine: learns each device's normal behaviour, flags what isn't.

Detectors
---------
new_device    a MAC address never seen before shows up (after network learning)
new_dns       a device looks up a domain it has never looked up before
unusual_hour  a device talks to the internet at an hour it is normally silent
volume_spike  a device sends far more data in an hour than it usually does
lan_scan      a device opens connections to many LAN hosts/ports within a minute

Every baseline detector stays quiet during the learning window
(cfg.learning_hours from the first packet ever seen), and new_dns also stays
quiet for a device's own grace period (cfg.device_grace_hours) after it joins.
The scan detector needs no baseline, so it is always on.

All times come from packet timestamps, never the wall clock, so a pcap
recorded last week is judged exactly as it would have been live.
"""

from __future__ import annotations

import statistics
import sqlite3
import time
from dataclasses import dataclass

from . import db
from .config import SEVERITIES, Config
from .domains import registrable
from .packets import Observation, is_external, is_randomized_mac, is_unicast_mac

FLUSH_SECONDS = 5.0
FLUSH_PACKETS = 5000


def day_hour(ts: float) -> tuple[str, int]:
    t = time.localtime(ts)
    return time.strftime("%Y-%m-%d", t), t.tm_hour


def fmt_time(ts: float) -> str:
    return time.strftime("%a %Y-%m-%d %H:%M", time.localtime(ts))


def vendor_for(mac: str) -> str | None:
    if is_randomized_mac(mac):
        return None
    try:
        from scapy.config import conf

        if conf.manufdb is None:
            return None
        found = conf.manufdb.lookup(mac)
        short, long = found if isinstance(found, tuple) else (found, found)
        if not short or ":" in str(short):
            return None
        return str(long or short)
    except Exception:
        return None


def display_name(dev: dict) -> str:
    if dev.get("label"):
        return dev["label"]
    if dev.get("hostname"):
        return dev["hostname"]
    tail = dev["mac"][-8:]
    if dev.get("vendor"):
        return f"{dev['vendor']} device ({tail})"
    return f"Unknown device ({tail})"


@dataclass
class Profile:
    """A device's history up to (not including) the current day."""

    days: int
    active_days: list[int]          # per hour: days with real internet activity
    spike_threshold: float          # ext bytes per hour that counts as a spike
    peak_bytes: int = 0             # busiest hour so far

    def ratio(self, hour: int) -> float:
        return self.active_days[hour] / self.days if self.days else 1.0


class Engine:
    def __init__(self, conn: sqlite3.Connection, cfg: Config, notifier=None):
        self.conn, self.cfg, self.notifier = conn, cfg, notifier
        start = db.get_meta(conn, "sensor_start")
        self.sensor_start: float | None = float(start) if start else None
        self.last_ts: float = float(db.get_meta(conn, "last_ts", "0"))

        self.devices: dict[str, dict] = {
            r["mac"]: dict(r) for r in conn.execute("SELECT * FROM devices")
        }
        self.known_domains: dict[str, set[str]] = {}
        for r in conn.execute("SELECT mac, domain FROM device_domains"):
            self.known_domains.setdefault(r["mac"], set()).add(r["domain"])
        self.network_domains = {d for s in self.known_domains.values() for d in s}

        self.ip_domain: dict[str, str] = {}        # resolved IP -> DNS name
        self.fanout: dict[str, dict[tuple, float]] = {}
        self.profiles: dict[tuple[str, str], Profile | None] = {}
        self.hour_totals: dict[tuple[str, str, int], dict] = {}

        self._dirty_devices: set[str] = set()
        self._domains: dict[tuple[str, str], list] = {}
        self._activity: dict[tuple[str, str, int], list[int]] = {}
        self._dests: dict[tuple, list] = {}
        self._last_flush_ts = 0.0
        self._since_flush = 0

        self.packets = 0
        self.alerts = 0

    # -- learning state ---------------------------------------------------

    def network_learning(self, ts: float) -> bool:
        return self.sensor_start is None or ts < self.sensor_start + self.cfg.learning_hours * 3600

    def in_grace(self, mac: str, ts: float) -> bool:
        dev = self.devices.get(mac)
        return dev is not None and ts < dev["first_seen"] + self.cfg.device_grace_hours * 3600

    # -- entry point ------------------------------------------------------

    def process(self, obs: Observation | None) -> None:
        if obs is None:
            return
        ts = obs.ts
        self.packets += 1
        if self.sensor_start is None:
            self.sensor_start = ts
            db.set_meta(self.conn, "sensor_start", ts)
        self.last_ts = max(self.last_ts, ts)

        for name, ip in obs.dns_answers:
            self.ip_domain[ip] = name

        if is_unicast_mac(obs.src_mac):
            self._touch_device(obs)
            if obs.dns_query and obs.dst_port == 53:
                self._on_dns_query(obs)
            if obs.dst_ip:
                self._on_traffic(obs)

        self._since_flush += 1
        if self._since_flush >= FLUSH_PACKETS or ts - self._last_flush_ts >= FLUSH_SECONDS:
            self.flush()

    # -- devices ----------------------------------------------------------

    def _touch_device(self, obs: Observation) -> None:
        mac, ts = obs.src_mac, obs.ts
        dev = self.devices.get(mac)
        is_new = dev is None
        if is_new:
            dev = {
                "mac": mac, "first_seen": ts, "last_seen": ts, "last_ip": None,
                "hostname": None, "vendor": vendor_for(mac), "label": None,
                "randomized": int(is_randomized_mac(mac)), "packets": 0, "bytes": 0,
            }
            self.devices[mac] = dev
        dev["last_seen"] = max(dev["last_seen"], ts)
        dev["packets"] += 1
        dev["bytes"] += obs.length
        ip = obs.src_ip
        # Packets the router forwards from the internet carry its MAC with a
        # public source IP; only LAN addresses describe the device itself.
        if ip and ip != "0.0.0.0" and not is_external(ip) and not ip.startswith(("fe80", "169.254.")):
            if ":" not in ip or not dev["last_ip"]:
                dev["last_ip"] = ip
        if obs.dhcp_hostname:
            dev["hostname"] = obs.dhcp_hostname
        self._dirty_devices.add(mac)

        if is_new:
            self._flush_devices()
            if not self.network_learning(ts):
                lines = [
                    f"MAC: {mac}" + (" (randomized: likely a phone or tablet using a private Wi-Fi address)" if dev["randomized"] else ""),
                    f"Vendor: {dev['vendor'] or 'unknown'}",
                    f"IP: {dev['last_ip'] or 'not seen yet'}",
                    f"First packet: {fmt_time(ts)}",
                ]
                self._alert("new_device", "medium", mac,
                            f"New device on the network: {self._name(mac)}",
                            "\n".join(lines), f"new_device:{mac}", ts)

    # -- DNS --------------------------------------------------------------

    def _on_dns_query(self, obs: Observation) -> None:
        dom = registrable(obs.dns_query, self.cfg.ignore_domains)
        if not dom:
            return
        mac, ts = obs.src_mac, obs.ts
        pend = self._domains.get((mac, dom))
        if pend:
            pend[1] = ts
            pend[2] += 1
        else:
            self._domains[(mac, dom)] = [ts, ts, 1, obs.dns_query]

        known = self.known_domains.setdefault(mac, set())
        if dom in known:
            return
        known.add(dom)
        new_to_network = dom not in self.network_domains
        self.network_domains.add(dom)
        if self.network_learning(ts) or self.in_grace(mac, ts):
            return

        severity = "medium" if new_to_network else "low"
        lines = [
            f"Query: {obs.dns_query}",
            "No device on this network has looked this domain up before." if new_to_network
            else "Other devices on the network already use this domain.",
        ]
        _, hour = day_hour(ts)
        prof = self._profile(mac, ts)
        if prof and prof.ratio(hour) < self.cfg.rare_hour_ratio:
            severity = _bump(severity)
            lines.append(f"It happened at {hour:02d}:00, an hour when this device is usually silent.")
        lines.append(f"When: {fmt_time(ts)}")
        self._alert("new_dns", severity, mac,
                    f"{self._name(mac)} looked up a new domain: {dom}",
                    "\n".join(lines), f"new_dns:{mac}:{dom}", ts)

    # -- traffic ----------------------------------------------------------

    def _on_traffic(self, obs: Observation) -> None:
        mac, ts = obs.src_mac, obs.ts
        ext = is_external(obs.dst_ip)
        day, hour = day_hour(ts)

        act = self._activity.setdefault((mac, day, hour), [0, 0, 0, 0])
        act[0] += 1
        act[1] += obs.length
        if ext:
            act[2] += 1
            act[3] += obs.length

        if is_unicast_mac(obs.dst_mac):
            key = (mac, obs.dst_ip, obs.dst_port or 0, obs.proto or "?")
            name = self.ip_domain.get(obs.dst_ip)
            d = self._dests.get(key)
            if d:
                d[1] = ts
                d[2] += 1
                d[3] += obs.length
                d[4] = d[4] or name
            else:
                self._dests[key] = [ts, ts, 1, obs.length, name]

        if obs.tcp_syn and not ext:
            self._check_fanout(obs)
        if ext and not self.network_learning(ts):
            self._check_hour(obs, day, hour)

    def _check_hour(self, obs: Observation, day: str, hour: int) -> None:
        mac, ts = obs.src_mac, obs.ts
        key = (mac, day, hour)
        tot = self.hour_totals.get(key)
        if tot is None:
            row = self.conn.execute(
                "SELECT ext_packets, ext_bytes FROM activity WHERE mac=? AND day=? AND hour=?", key
            ).fetchone()
            tot = {"p": row[0] if row else 0, "b": row[1] if row else 0, "dests": {}, "hour_alerted": False, "spiked": False}
            self.hour_totals[key] = tot
        tot["p"] += 1
        tot["b"] += obs.length
        target = self.ip_domain.get(obs.dst_ip) or obs.dst_ip
        label = f"{target}:{obs.dst_port}" if obs.dst_port else target
        if len(tot["dests"]) < 8 or label in tot["dests"]:
            tot["dests"][label] = tot["dests"].get(label, 0) + 1

        prof = self._profile(mac, ts)
        if prof is None:
            return
        if (not tot["hour_alerted"] and tot["p"] >= self.cfg.rare_hour_min_packets
                and prof.ratio(hour) < self.cfg.rare_hour_ratio):
            tot["hour_alerted"] = True
            top = sorted(tot["dests"].items(), key=lambda kv: -kv[1])[:5]
            lines = [
                f"{tot['p']} packets to the internet at {hour:02d}:00.",
                f"Over the last {prof.days} days it was active at this hour on {prof.active_days[hour]} day(s).",
                "Talking to: " + ", ".join(f"{k} ({v})" for k, v in top),
                f"When: {fmt_time(ts)}",
            ]
            self._alert("unusual_hour", "medium", mac,
                        f"{self._name(mac)} is active at an unusual hour ({hour:02d}:00)",
                        "\n".join(lines), f"unusual_hour:{mac}:{day}:{hour}", ts)
        if not tot["spiked"] and tot["b"] >= prof.spike_threshold:
            tot["spiked"] = True
            top = sorted(tot["dests"].items(), key=lambda kv: -kv[1])[:5]
            lines = [
                f"Crossed {_mb(prof.spike_threshold)} sent to the internet within the {hour:02d}:00 hour.",
                f"Its busiest hour in the last {prof.days} days was {_mb(prof.peak_bytes)}.",
                "Talking to: " + ", ".join(f"{k} ({v})" for k, v in top),
                f"When: {fmt_time(ts)}",
            ]
            self._alert("volume_spike", "medium", mac,
                        f"{self._name(mac)} is uploading much more than usual",
                        "\n".join(lines), f"volume_spike:{mac}:{day}:{hour}", ts)

    def _check_fanout(self, obs: Observation) -> None:
        mac, ts = obs.src_mac, obs.ts
        targets = self.fanout.setdefault(mac, {})
        targets[(obs.dst_ip, obs.dst_port)] = ts
        if len(targets) < self.cfg.fanout_targets:
            return
        cutoff = ts - self.cfg.fanout_window
        for k in [k for k, t in targets.items() if t < cutoff]:
            del targets[k]
        if len(targets) < self.cfg.fanout_targets:
            return
        hosts = sorted({ip for ip, _ in targets})
        ports = sorted({p for _, p in targets})
        lines = [
            f"{len(targets)} new connection attempts inside {self.cfg.fanout_window}s "
            f"to {len(hosts)} LAN host(s) on {len(ports)} port(s).",
            "Hosts: " + ", ".join(hosts[:10]) + (" ..." if len(hosts) > 10 else ""),
            "Ports: " + ", ".join(map(str, ports[:15])) + (" ..." if len(ports) > 15 else ""),
            f"When: {fmt_time(ts)}",
        ]
        self._alert("lan_scan", "high", mac,
                    f"{self._name(mac)} looks like it is scanning the LAN",
                    "\n".join(lines), f"lan_scan:{mac}:{int(ts // 600)}", ts)
        targets.clear()

    # -- baselines --------------------------------------------------------

    def _profile(self, mac: str, ts: float) -> Profile | None:
        day, _ = day_hour(ts)
        key = (mac, day)
        if key in self.profiles:
            return self.profiles[key]
        self.flush()  # make sure earlier days are on disk
        rows = self.conn.execute(
            "SELECT day, hour, packets, ext_packets, ext_bytes FROM activity WHERE mac=? AND day<?",
            (mac, day),
        ).fetchall()
        days = {r["day"] for r in rows if r["packets"] > 0}
        prof = None
        if len(days) >= self.cfg.min_baseline_days:
            active_floor = max(1, self.cfg.rare_hour_min_packets // 2)
            active: list[set[str]] = [set() for _ in range(24)]
            hourly_bytes = []
            for r in rows:
                if r["ext_packets"] >= active_floor:
                    active[r["hour"]].add(r["day"])
                if r["ext_bytes"] > 0:
                    hourly_bytes.append(r["ext_bytes"])
            threshold = float(self.cfg.spike_min_bytes)
            if len(hourly_bytes) >= 2:
                mean = statistics.fmean(hourly_bytes)
                std = statistics.pstdev(hourly_bytes)
                threshold = max(threshold, mean + self.cfg.spike_sigma * std, 3 * max(hourly_bytes))
            prof = Profile(days=len(days), active_days=[len(s) for s in active],
                           spike_threshold=threshold, peak_bytes=max(hourly_bytes, default=0))
        self.profiles[key] = prof
        return prof

    # -- alerts -----------------------------------------------------------

    def _name(self, mac: str) -> str:
        """Display name, reading the label fresh: the dashboard may have set it."""
        dev = dict(self.devices[mac])
        row = self.conn.execute("SELECT label FROM devices WHERE mac = ?", (mac,)).fetchone()
        if row and row[0]:
            dev["label"] = row[0]
        return display_name(dev)

    def _alert(self, kind: str, severity: str, mac: str | None, title: str,
               detail: str, dedupe: str, ts: float) -> dict | None:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO alerts (ts, kind, severity, mac, title, detail, dedupe) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, kind, severity, mac, title, detail, dedupe),
        )
        if cur.rowcount == 0:
            return None
        alert = {"id": cur.lastrowid, "ts": ts, "kind": kind, "severity": severity,
                 "mac": mac, "title": title, "detail": detail}
        self.alerts += 1
        if self.notifier is not None and self.notifier.submit(alert):
            self.conn.execute("UPDATE alerts SET pushed = 1 WHERE id = ?", (alert["id"],))
        self.conn.commit()
        return alert

    # -- persistence ------------------------------------------------------

    def _flush_devices(self) -> None:
        if not self._dirty_devices:
            return
        self.conn.executemany(
            """INSERT INTO devices (mac, first_seen, last_seen, last_ip, hostname, vendor, randomized, packets, bytes)
               VALUES (:mac, :first_seen, :last_seen, :last_ip, :hostname, :vendor, :randomized, :packets, :bytes)
               ON CONFLICT(mac) DO UPDATE SET
                 last_seen = excluded.last_seen, last_ip = excluded.last_ip,
                 hostname = COALESCE(excluded.hostname, devices.hostname),
                 vendor = COALESCE(devices.vendor, excluded.vendor),
                 packets = excluded.packets, bytes = excluded.bytes""",
            [self.devices[m] for m in self._dirty_devices],
        )
        self._dirty_devices.clear()

    def flush(self) -> None:
        self._flush_devices()
        if self._domains:
            self.conn.executemany(
                """INSERT INTO device_domains (mac, domain, first_seen, last_seen, queries, sample_qname)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mac, domain) DO UPDATE SET
                     last_seen = MAX(device_domains.last_seen, excluded.last_seen),
                     queries = device_domains.queries + excluded.queries""",
                [(m, d, *v) for (m, d), v in self._domains.items()],
            )
            self._domains.clear()
        if self._activity:
            self.conn.executemany(
                """INSERT INTO activity (mac, day, hour, packets, bytes, ext_packets, ext_bytes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mac, day, hour) DO UPDATE SET
                     packets = activity.packets + excluded.packets,
                     bytes = activity.bytes + excluded.bytes,
                     ext_packets = activity.ext_packets + excluded.ext_packets,
                     ext_bytes = activity.ext_bytes + excluded.ext_bytes""",
                [(*k, *v) for k, v in self._activity.items()],
            )
            self._activity.clear()
        if self._dests:
            self.conn.executemany(
                """INSERT INTO destinations (mac, dst_ip, dst_port, proto, first_seen, last_seen, packets, bytes, domain)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mac, dst_ip, dst_port, proto) DO UPDATE SET
                     last_seen = MAX(destinations.last_seen, excluded.last_seen),
                     packets = destinations.packets + excluded.packets,
                     bytes = destinations.bytes + excluded.bytes,
                     domain = COALESCE(excluded.domain, destinations.domain)""",
                [(*k, *v) for k, v in self._dests.items()],
            )
            self._dests.clear()
        db.set_meta(self.conn, "last_ts", self.last_ts)
        self.conn.commit()
        self._last_flush_ts = self.last_ts
        self._since_flush = 0
        if len(self.hour_totals) > 512:
            current = day_hour(self.last_ts)
            self.hour_totals = {k: v for k, v in self.hour_totals.items() if k[1:] == current}


def _bump(severity: str) -> str:
    i = SEVERITIES.index(severity)
    return SEVERITIES[min(i + 1, len(SEVERITIES) - 1)]


def _mb(n: float) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    return f"{n / 1000:.0f} KB"
