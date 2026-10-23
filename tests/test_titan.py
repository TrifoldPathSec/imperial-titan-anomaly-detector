import os
import time

import pytest
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

os.environ["TZ"] = "UTC"
time.tzset()

from titan import db  # noqa: E402
from titan.capture import ingest  # noqa: E402
from titan.config import Config  # noqa: E402
from titan.domains import registrable  # noqa: E402
from titan.engine import Engine  # noqa: E402
from titan.notify import Notifier  # noqa: E402
from titan.packets import Observation, is_external, is_randomized_mac, parse  # noqa: E402
from titan.synth import build  # noqa: E402

DAY = 86400
T0 = 1790000000.0 - (1790000000 % DAY)  # a UTC midnight
DEV = "00:00:5e:00:53:10"
GW = "00:00:5e:00:53:01"


def stamp(pkt, ts):
    pkt.time = ts
    return pkt


# -- parsing ----------------------------------------------------------------

def test_parse_dns_query_and_answer():
    q = stamp(Ether(src=DEV, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.1")
              / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="Api.Example.com.")), T0)
    o = parse(q)
    assert o.dns_query == "api.example.com" and o.dst_port == 53 and o.src_mac == DEV

    a = stamp(Ether(src=GW, dst=DEV) / IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=5555)
              / DNS(qr=1, qd=DNSQR(qname="api.example.com"),
                    an=DNSRR(rrname="api.example.com", type="A", rdata="203.0.113.5")), T0)
    assert parse(Ether(bytes(a))).dns_answers == [("api.example.com", "203.0.113.5")]


def test_parse_dhcp_hostname_arp_and_syn():
    d = Ether(src=DEV, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) \
        / BOOTP() / DHCP(options=[("message-type", "request"), ("requested_addr", "192.168.1.10"),
                                  ("hostname", b"living-room-tv"), "end"])
    o = parse(stamp(d, T0))
    assert o.dhcp_hostname == "living-room-tv" and o.src_ip == "192.168.1.10"

    o = parse(stamp(Ether(src=DEV) / ARP(psrc="192.168.1.10", hwsrc=DEV), T0))
    assert o.proto == "arp" and o.src_ip == "192.168.1.10"

    o = parse(stamp(Ether(src=DEV, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(dport=22, flags="S"), T0))
    assert o.tcp_syn and o.dst_port == 22
    o = parse(stamp(Ether(src=DEV, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(dport=22, flags="SA"), T0))
    assert not o.tcp_syn


def test_address_helpers():
    assert is_external("8.8.8.8") and is_external("203.0.113.9")
    assert not is_external("192.168.1.5") and not is_external("224.0.0.251") and not is_external("fe80::1")
    assert is_randomized_mac("da:a1:19:00:00:01") and not is_randomized_mac(DEV)


def test_registrable_domain():
    assert registrable("img.cdn.example.com") == "example.com"
    assert registrable("www.bbc.co.uk") == "bbc.co.uk"
    assert registrable("someone.github.io") == "someone.github.io"
    assert registrable("printer.local", ("local",)) is None
    assert registrable("10.in-addr.arpa", ("arpa",)) is None
    assert registrable("router") is None and registrable("192.168.1.1") is None


# -- engine -----------------------------------------------------------------

def make_engine(tmp_path, **kw):
    cfg = Config(db_path=tmp_path / "t.db", learning_hours=24, device_grace_hours=1,
                 min_baseline_days=3, **kw)
    return Engine(db.connect(cfg.db_path), cfg)


def obs(ts, mac=DEV, **kw):
    base = dict(ts=ts, src_mac=mac, dst_mac=GW, length=100, src_ip="192.168.1.10")
    base.update(kw)
    return Observation(**base)


def kinds(engine):
    engine.flush()
    return [r["kind"] for r in engine.conn.execute("SELECT kind FROM alerts ORDER BY ts")]


def test_learning_window_suppresses_alerts(tmp_path):
    e = make_engine(tmp_path)
    e.process(obs(T0, dns_query="a.example.com", dst_ip="192.168.1.1", dst_port=53))
    e.process(obs(T0 + 3600, mac="00:00:5e:00:53:77", src_ip="192.168.1.77"))
    e.process(obs(T0 + 7200, dns_query="b.example.org", dst_ip="192.168.1.1", dst_port=53))
    assert kinds(e) == []


def test_new_device_and_new_domain_after_learning(tmp_path):
    e = make_engine(tmp_path)
    e.process(obs(T0, dns_query="a.example.com", dst_ip="192.168.1.1", dst_port=53))
    later = T0 + 2 * DAY
    e.process(obs(later, mac="00:00:5e:00:53:77", src_ip="192.168.1.77"))
    e.process(obs(later + 60, dns_query="www.example.com", dst_ip="192.168.1.1", dst_port=53))  # same domain
    e.process(obs(later + 120, dns_query="x.newsite.example", dst_ip="192.168.1.1", dst_port=53))
    e.process(obs(later + 180, dns_query="y.newsite.example", dst_ip="192.168.1.1", dst_port=53))  # deduped
    assert kinds(e) == ["new_device", "new_dns"]
    sev = e.conn.execute("SELECT severity FROM alerts WHERE kind='new_dns'").fetchone()[0]
    assert sev == "medium"  # nobody on the network used it before


def test_label_set_while_running_is_used_in_alerts(tmp_path):
    e = make_engine(tmp_path)
    e.process(obs(T0))
    e.conn.execute("UPDATE devices SET label = 'Study laptop' WHERE mac = ?", (DEV,))
    e.conn.commit()
    e.process(obs(T0 + 2 * DAY, dns_query="x.newsite.example", dst_ip="192.168.1.1", dst_port=53))
    e.flush()
    title = e.conn.execute("SELECT title FROM alerts").fetchone()[0]
    assert title.startswith("Study laptop ")
    assert e.conn.execute("SELECT label FROM devices WHERE mac = ?", (DEV,)).fetchone()[0] == "Study laptop"


def test_new_device_grace_period(tmp_path):
    e = make_engine(tmp_path)
    e.process(obs(T0))
    later = T0 + 2 * DAY
    new = "00:00:5e:00:53:88"
    e.process(obs(later, mac=new, src_ip="192.168.1.88"))
    e.process(obs(later + 60, mac=new, dns_query="a.example.net", dst_ip="192.168.1.1", dst_port=53))
    e.process(obs(later + 2 * 3600, mac=new, dns_query="b.example.info", dst_ip="192.168.1.1", dst_port=53))
    assert kinds(e) == ["new_device", "new_dns"]


def test_unusual_hour_and_volume_spike(tmp_path):
    e = make_engine(tmp_path, spike_min_bytes=50_000)
    for d in range(5):  # evenings only, ~30 packets an hour
        for i in range(30):
            e.process(obs(T0 + d * DAY + 20 * 3600 + i, dst_ip="203.0.113.5", dst_port=443, length=500))
    night = T0 + 5 * DAY + 3 * 3600
    for i in range(25):
        e.process(obs(night + i, dst_ip="203.0.113.99", dst_port=8443))
    evening = T0 + 5 * DAY + 20 * 3600
    for i in range(200):
        e.process(obs(evening + i, dst_ip="203.0.113.5", dst_port=443, length=1400))
    assert kinds(e) == ["unusual_hour", "volume_spike"]


def test_lan_scan(tmp_path):
    e = make_engine(tmp_path, fanout_targets=20)
    for i in range(1, 30):
        e.process(obs(T0 + i * 0.1, dst_ip=f"192.168.1.{i}", dst_port=22, proto="tcp", tcp_syn=True))
    assert kinds(e) == ["lan_scan"]  # no baseline needed, even during learning


def test_slow_lan_connections_are_not_a_scan(tmp_path):
    e = make_engine(tmp_path, fanout_targets=20, fanout_window=60)
    for i in range(1, 60):
        e.process(obs(T0 + i * 10, dst_ip=f"192.168.1.{i}", dst_port=445, proto="tcp", tcp_syn=True))
    assert kinds(e) == []


def test_state_survives_restart(tmp_path):
    e = make_engine(tmp_path)
    e.process(obs(T0, dns_query="a.example.com", dst_ip="192.168.1.1", dst_port=53))
    e.flush()
    e2 = Engine(db.connect(e.cfg.db_path), e.cfg)
    e2.process(obs(T0 + 2 * DAY, dns_query="www.example.com", dst_ip="192.168.1.1", dst_port=53))
    assert kinds(e2) == []


def test_synthetic_week_catches_every_planted_incident(tmp_path):
    pcap = tmp_path / "demo.pcap"
    build(str(pcap))
    cfg = Config(db_path=tmp_path / "demo.db", spike_min_bytes=1_000_000)
    e = Engine(db.connect(cfg.db_path), cfg)
    ingest(e, [str(pcap)])
    rows = e.conn.execute("SELECT kind, severity, title FROM alerts ORDER BY ts").fetchall()
    assert [(r["kind"], r["severity"]) for r in rows] == [
        ("new_dns", "high"), ("unusual_hour", "medium"),           # TV at 03:12
        ("new_device", "medium"), ("lan_scan", "high"),             # intruder at 10:05
        ("new_dns", "medium"),                                      # paste site
        ("new_dns", "medium"), ("volume_spike", "medium"),          # upload
    ]
    assert all(r["title"] for r in rows)


# -- notifications ----------------------------------------------------------

def alert(sev="medium", kind="new_dns"):
    return {"id": 1, "ts": T0, "kind": kind, "severity": sev, "mac": DEV, "title": "t → x", "detail": "d"}


def test_notifier_threshold_and_rate_limit():
    sent = []
    cfg = Config(ntfy_topic="topic", push_min_severity="medium", push_per_10min=2)
    n = Notifier(cfg, sender=lambda *a: sent.append(a))
    assert not n.submit(alert("low"))
    assert n.submit(alert()) and n.submit(alert("high"))
    assert not n.submit(alert())  # over the limit
    n.close()
    assert len(sent) == 2 and n.suppressed == 1


def test_notifier_disabled_without_topic():
    assert not Notifier(Config(ntfy_topic="")).submit(alert("high"))


def test_ntfy_request_shape(monkeypatch):
    captured = {}

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b""

    def fake_urlopen(req, timeout):
        captured.update(url=req.full_url, headers=dict(req.header_items()), body=req.data)
        return Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    Notifier(Config(ntfy_topic="abc", ntfy_token="tok"))._post("Title → x", "body", "high", "lan_scan")
    assert captured["url"] == "https://ntfy.sh/abc"
    assert captured["headers"]["Priority"] == "5"
    assert captured["headers"]["Title"] == "Title ? x"
    assert captured["headers"]["Authorization"] == "Bearer tok"


# -- dashboard --------------------------------------------------------------

@pytest.fixture()
def client(tmp_path):
    from titan.dashboard import create_app

    pcap = tmp_path / "demo.pcap"
    build(str(pcap))
    cfg = Config(db_path=tmp_path / "demo.db", spike_min_bytes=1_000_000)
    ingest(Engine(db.connect(cfg.db_path), cfg), [str(pcap)])
    app = create_app(cfg)
    app.testing = True
    return app.test_client()


def test_dashboard_pages(client):
    assert b"living-room-tv" in client.get("/").data
    page = client.get("/device/00:00:5e:00:53:20").data
    assert b"c2-relay.example" in page and b"quietband" in page
    assert b"LAN scan" in client.get("/alerts").data
    assert client.get("/device/00:00:00:00:00:00").status_code == 404
    assert len(client.get("/api/alerts").json["alerts"]) == 7


def test_dashboard_posts_need_same_origin(client):
    origin = {"Origin": "http://localhost"}
    assert client.post("/alerts/ack", data={"id": "1"}).status_code == 403
    assert client.post("/alerts/ack", data={"id": "1"}, headers={"Origin": "http://evil.example"}).status_code == 403
    r = client.post("/alerts/ack", data={"id": "1", "next": "//evil.example"}, headers=origin)
    assert r.status_code == 302 and r.headers["Location"].endswith("/alerts")
    assert client.get("/api/alerts").json["alerts"][-1]["acked"] == 1
    client.post("/device/00:00:5e:00:53:20/label", data={"label": "Living room TV"}, headers=origin)
    assert b"Living room TV" in client.get("/").data
