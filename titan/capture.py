"""Feed packets to the engine: live from an interface, or from pcap files."""

from __future__ import annotations

import sys
import time

from scapy.all import PcapReader, sniff
from scapy.error import Scapy_Exception

from .engine import Engine
from .packets import parse


def _progress(engine: Engine, started: float, final: bool = False) -> None:
    rate = engine.packets / max(time.time() - started, 0.001)
    end = "\n" if final else "\r"
    print(f"[titan] {engine.packets:,} packets  {engine.alerts} alerts  {rate:,.0f} pkt/s   ",
          end=end, file=sys.stderr, flush=True)


def live(engine: Engine, iface: str | None, bpf: str | None = None, promisc: bool = False) -> None:
    # macOS refuses promiscuous mode on Wi-Fi, and on Wi-Fi it adds nothing:
    # the access point only delivers our own unicast plus broadcast/multicast.
    # It is only useful on a wired mirror/SPAN port, hence opt-in.
    started = last = time.time()

    def handle(pkt):
        nonlocal last
        engine.process(parse(pkt))
        if time.time() - last >= 5:
            last = time.time()
            engine.flush()  # keep the dashboard current on quiet networks
            _progress(engine, started)

    print(f"[titan] sniffing on {iface or 'default interface'}"
          + (f" with filter '{bpf}'" if bpf else "")
          + (" in promiscuous mode" if promisc else "") + "  (Ctrl-C to stop)", file=sys.stderr)
    try:
        sniff(iface=iface, filter=bpf, prn=handle, store=False, promisc=promisc)
    except PermissionError:
        sys.exit("[titan] permission denied opening the capture device: run with sudo")
    except Scapy_Exception as exc:
        sys.exit(f"[titan] capture failed: {exc}")
    finally:
        engine.flush()
        _progress(engine, started, final=True)


def ingest(engine: Engine, paths: list[str]) -> None:
    started = time.time()
    for path in paths:
        print(f"[titan] reading {path}", file=sys.stderr)
        with PcapReader(path) as reader:
            for i, pkt in enumerate(reader, 1):
                engine.process(parse(pkt))
                if i % 20000 == 0:
                    _progress(engine, started)
    engine.flush()
    _progress(engine, started, final=True)
