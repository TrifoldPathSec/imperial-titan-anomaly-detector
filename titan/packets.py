"""Turn a raw Scapy packet into one flat Observation.

The engine never touches Scapy objects, which keeps detection logic easy to
test and lets live capture and pcap ingest share one code path.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

DNS_PORT = 53
QTYPE_A, QTYPE_AAAA = 1, 28


@dataclass
class Observation:
    ts: float
    src_mac: str
    dst_mac: str
    length: int
    src_ip: str | None = None
    dst_ip: str | None = None
    proto: str | None = None          # "tcp", "udp", "icmp", "arp", ...
    dst_port: int | None = None
    tcp_syn: bool = False             # SYN without ACK: a new connection attempt
    dhcp_hostname: str | None = None
    dns_query: str | None = None      # name asked in a standard DNS query (port 53)
    dns_answers: list[tuple[str, str]] = field(default_factory=list)  # (name, ip)


def is_unicast_mac(mac: str) -> bool:
    if not mac or mac == "00:00:00:00:00:00":
        return False
    return not int(mac.split(":")[0], 16) & 0x01


def is_randomized_mac(mac: str) -> bool:
    """Locally administered bit set: typical of phones' private Wi-Fi addresses."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def is_external(ip: str | None) -> bool:
    """True for addresses on the public internet."""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # The RFC 5737 / 3849 documentation ranges are not "global" to ipaddress,
    # but the synthetic demo uses them to stand in for internet servers.
    if _is_doc_range(a):
        return True
    return a.is_global and not a.is_multicast


_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def _is_doc_range(a) -> bool:
    return any(a in n for n in _DOC_NETS if n.version == a.version)


def _decode(name) -> str:
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    return str(name).rstrip(".").lower()


def parse(pkt) -> Observation | None:
    if not pkt.haslayer(Ether):
        return None
    eth = pkt[Ether]
    if not eth.src:
        return None
    obs = Observation(
        ts=float(pkt.time),
        src_mac=eth.src.lower(),
        dst_mac=(eth.dst or "ff:ff:ff:ff:ff:ff").lower(),
        length=len(pkt),
    )

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        obs.proto = "arp"
        if arp.psrc and arp.psrc != "0.0.0.0":
            obs.src_ip = arp.psrc
        return obs

    if pkt.haslayer(IP):
        obs.src_ip, obs.dst_ip = pkt[IP].src, pkt[IP].dst
        obs.proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(pkt[IP].proto, str(pkt[IP].proto))
    elif pkt.haslayer(IPv6):
        obs.src_ip, obs.dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        obs.proto = "ipv6"
    else:
        return obs

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        obs.proto, obs.dst_port = "tcp", int(tcp.dport)
        flags = int(tcp.flags)
        obs.tcp_syn = bool(flags & 0x02) and not flags & 0x10
    elif pkt.haslayer(UDP):
        obs.proto, obs.dst_port = "udp", int(pkt[UDP].dport)

    if obs.src_ip == "0.0.0.0":
        obs.src_ip = None

    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "hostname":
                obs.dhcp_hostname = _decode(opt[1])
            elif isinstance(opt, tuple) and opt[0] == "requested_addr" and not obs.src_ip and opt[1] != "0.0.0.0":
                obs.src_ip = str(opt[1])

    if pkt.haslayer(DNS) and pkt.haslayer(UDP) and DNS_PORT in (pkt[UDP].sport, pkt[UDP].dport):
        dns = pkt[DNS]
        try:
            if dns.qr == 0 and dns.qd:
                obs.dns_query = _decode(dns.qd[0].qname)
            elif dns.qr == 1 and dns.an:
                for rr in dns.an:
                    if rr.type in (QTYPE_A, QTYPE_AAAA):
                        obs.dns_answers.append((_decode(rr.rrname), str(rr.rdata)))
        except (IndexError, AttributeError, TypeError):
            pass  # malformed DNS: keep the flow information anyway

    return obs
