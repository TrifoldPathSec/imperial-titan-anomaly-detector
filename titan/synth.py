"""Build a synthetic home-network pcap: a quiet week, then a day of trouble.

Everything is fake on purpose: MACs come from the RFC 7042 documentation
block (00:00:5e:00:53:xx), internet servers from the RFC 5737 documentation
ranges, and every domain uses the reserved `.example` TLD.

Days 1-7: a laptop, a phone, a smart TV and a thermostat behave normally.
Day 8 contains four planted incidents:
  03:12  the TV wakes up and beacons to a domain nobody has used before
  10:05  an unknown device joins and sweeps the LAN for open ports
  14:30  the laptop visits a never-seen paste site
  21:00  the laptop uploads far more than it ever has
"""

from __future__ import annotations

import random
import time

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

LAN = "192.168.50."
ROUTER = {"mac": "00:00:5e:00:53:01", "ip": LAN + "1"}

DEVICES = {
    "laptop": {"mac": "00:00:5e:00:53:10", "ip": LAN + "10", "host": "study-laptop",
               "hours": range(8, 24), "sessions": (2, 4),
               "sites": {"news.example": "198.51.100.10", "mail.example": "198.51.100.11",
                         "docs.example": "198.51.100.12", "video.example": "198.51.100.13",
                         "search.example": "198.51.100.14"}},
    "phone": {"mac": "00:00:5e:00:53:11", "ip": LAN + "11", "host": "pixel-phone",
              "hours": range(7, 23), "sessions": (1, 3),
              "sites": {"chat.example": "198.51.100.20", "maps.example": "198.51.100.21",
                        "search.example": "198.51.100.14", "photos.example": "198.51.100.22"}},
    "tv": {"mac": "00:00:5e:00:53:20", "ip": LAN + "20", "host": "living-room-tv",
           "hours": range(18, 24), "sessions": (2, 4),
           "sites": {"streaming.example": "203.0.113.10", "tv-vendor.example": "203.0.113.11"}},
    "thermostat": {"mac": "00:00:5e:00:53:30", "ip": LAN + "30", "host": "thermostat",
                   "hours": range(0, 24), "sessions": (1, 1),
                   "sites": {"iot-cloud.example": "203.0.113.20"}},
}
INTRUDER = {"mac": "00:00:5e:00:53:99", "ip": LAN + "99"}


class Builder:
    def __init__(self, seed: int = 9):
        self.rng = random.Random(seed)
        self.pkts = []

    def add(self, pkt, ts: float):
        pkt.time = ts
        self.pkts.append(pkt)

    def dhcp(self, dev, ts):
        opts = [("message-type", "request"), ("requested_addr", dev["ip"])]
        if dev.get("host"):
            opts.append(("hostname", dev["host"].encode()))
        mac_bytes = bytes.fromhex(dev["mac"].replace(":", ""))
        self.add(Ether(src=dev["mac"], dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
                 / UDP(sport=68, dport=67) / BOOTP(chaddr=mac_bytes) / DHCP(options=opts + ["end"]), ts)
        self.add(Ether(src=dev["mac"], dst="ff:ff:ff:ff:ff:ff")
                 / ARP(op=1, hwsrc=dev["mac"], psrc=dev["ip"], pdst=ROUTER["ip"]), ts + 0.2)

    def session(self, dev, ts, qname, server, packets, size=300, port=443):
        sport = self.rng.randint(40000, 60000)
        txid = self.rng.randint(1, 65535)
        self.add(Ether(src=dev["mac"], dst=ROUTER["mac"]) / IP(src=dev["ip"], dst=ROUTER["ip"])
                 / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=qname)), ts)
        self.add(Ether(src=ROUTER["mac"], dst=dev["mac"]) / IP(src=ROUTER["ip"], dst=dev["ip"])
                 / UDP(sport=53, dport=sport)
                 / DNS(id=txid, qr=1, ra=1, qd=DNSQR(qname=qname),
                       an=DNSRR(rrname=qname, type="A", ttl=300, rdata=server)), ts + 0.01)
        t = ts + 0.05
        sport += 1
        self.add(Ether(src=dev["mac"], dst=ROUTER["mac"]) / IP(src=dev["ip"], dst=server)
                 / TCP(sport=sport, dport=port, flags="S"), t)
        for i in range(packets - 1):
            t += self.rng.uniform(0.01, 0.4)
            self.add(Ether(src=dev["mac"], dst=ROUTER["mac"]) / IP(src=dev["ip"], dst=server)
                     / TCP(sport=sport, dport=port, flags="PA") / Raw(b"\x00" * size), t)
            if i % 3 == 0:  # some replies, which arrive via the router's MAC
                self.add(Ether(src=ROUTER["mac"], dst=dev["mac"]) / IP(src=server, dst=dev["ip"])
                         / TCP(sport=port, dport=sport, flags="PA") / Raw(b"\x00" * size), t + 0.005)


def day_start(day0: float, n: int) -> float:
    t = time.localtime(day0)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday + n, 0, 0, 0, 0, 0, -1))


def build(out: str, start: tuple[int, int, int] = (2026, 10, 1), days: int = 8, seed: int = 9) -> int:
    b = Builder(seed)
    rng = b.rng
    day0 = time.mktime((*start, 0, 0, 0, 0, 0, -1))

    for name, dev in DEVICES.items():
        b.dhcp(dev, day0 + 60 + list(DEVICES).index(name) * 30)

    for d in range(days):
        base = day_start(day0, d)
        for dev in DEVICES.values():
            for hour in dev["hours"]:
                lo, hi = dev["sessions"]
                for _ in range(rng.randint(lo, hi)):
                    ts = base + hour * 3600 + rng.uniform(120, 3500)
                    site, ip = rng.choice(list(dev["sites"].items()))
                    sub = rng.choice(["www", "api", "cdn", "static"])
                    n = 6 if dev is DEVICES["thermostat"] else rng.randint(15, 40)
                    b.session(dev, ts, f"{sub}.{site}", ip, n)
            # the phone pings for notifications overnight, but only a little
            if dev is DEVICES["phone"]:
                for hour in (0, 2, 4, 6):
                    b.session(dev, base + hour * 3600 + rng.uniform(60, 3000), "push.chat.example",
                              "198.51.100.20", 4, size=100)

    last = day_start(day0, days - 1)
    tv, laptop = DEVICES["tv"], DEVICES["laptop"]

    # 03:12 the TV beacons to a new domain at an hour it is always asleep
    t = last + 3 * 3600 + 12 * 60
    b.session(tv, t, "beacon.c2-relay.example", "203.0.113.66", 45, size=200, port=8443)

    # 10:05 an unknown device joins and sweeps the LAN
    t = last + 10 * 3600 + 5 * 60
    b.dhcp({"mac": INTRUDER["mac"], "ip": INTRUDER["ip"]}, t)
    t += 5
    for host in range(1, 41):
        for port in (22, 80):
            t += 0.05
            b.add(Ether(src=INTRUDER["mac"], dst=ROUTER["mac"]) / IP(src=INTRUDER["ip"], dst=LAN + str(host))
                  / TCP(sport=rng.randint(40000, 60000), dport=port, flags="S"), t)

    # 14:30 the laptop opens a paste site nobody here has used
    b.session(laptop, last + 14 * 3600 + 30 * 60, "files.paste-share.example", "198.51.100.66", 20)

    # 21:00 the laptop uploads ~3 MB, many times its usual hourly volume
    b.session(laptop, last + 21 * 3600 + 60, "upload.bulk-store.example", "198.51.100.77", 2200, size=1400)

    b.pkts.sort(key=lambda p: p.time)
    wrpcap(out, b.pkts)
    return len(b.pkts)
