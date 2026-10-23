"""Push alerts to a phone through ntfy (https://ntfy.sh).

Install the ntfy app, subscribe to the topic in .env, and every alert at or
above TITAN_PUSH_MIN_SEVERITY arrives as a notification. Pushes are sent from
a background thread so a slow network never stalls packet capture, and a
rate limit stops an alert storm from flooding the phone.
"""

from __future__ import annotations

import queue
import sys
import threading
import time
import urllib.request
from collections import deque

from .config import SEVERITIES, Config

PRIORITY = {"low": "2", "medium": "4", "high": "5"}
TAGS = {
    "new_device": "new,computer",
    "new_dns": "mag,globe_with_meridians",
    "unusual_hour": "crescent_moon,warning",
    "volume_spike": "chart_with_upwards_trend,warning",
    "lan_scan": "rotating_light",
    "test": "white_check_mark",
}
WINDOW = 600


def _header(text: str) -> str:
    # HTTP headers must be latin-1; keep them plain ASCII to be safe.
    return text.encode("ascii", "replace").decode("ascii")


class Notifier:
    def __init__(self, cfg: Config, enabled: bool = True, sender=None):
        self.cfg = cfg
        self.enabled = enabled and bool(cfg.ntfy_topic)
        self.sender = sender or self._post
        self.sent: deque[float] = deque()
        self.suppressed = 0
        self._q: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None

    def should_push(self, alert: dict) -> bool:
        return self.enabled and SEVERITIES.index(alert["severity"]) >= SEVERITIES.index(self.cfg.push_min_severity)

    def submit(self, alert: dict) -> bool:
        """Queue a push for this alert. Returns True if it will be sent."""
        if not self.should_push(alert):
            return False
        now = time.time()
        while self.sent and now - self.sent[0] > WINDOW:
            self.sent.popleft()
        if len(self.sent) >= self.cfg.push_per_10min:
            self.suppressed += 1
            return False
        self.sent.append(now)
        body = alert["detail"] or ""
        if self.suppressed:
            body += f"\n(+{self.suppressed} more alerts held back by the rate limit; see the dashboard)"
            self.suppressed = 0
        self._ensure_thread()
        self._q.put((alert["title"], body, alert["severity"], alert["kind"]))
        return True

    def _ensure_thread(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, name="titan-ntfy", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                self._q.task_done()
                return
            try:
                self.sender(*item)
            except Exception as exc:  # never let a push failure kill capture
                print(f"[titan] push failed: {exc}", file=sys.stderr)
            finally:
                self._q.task_done()

    def close(self, timeout: float = 10.0) -> None:
        """Wait (briefly) for queued pushes to go out."""
        if self._thread and self._thread.is_alive():
            self._q.put(None)
            self._thread.join(timeout)

    def _post(self, title: str, body: str, severity: str, kind: str) -> None:
        req = urllib.request.Request(
            f"{self.cfg.ntfy_server}/{self.cfg.ntfy_topic}",
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "Title": _header(title),
                "Priority": PRIORITY.get(severity, "3"),
                "Tags": TAGS.get(kind, "warning"),
            },
        )
        if self.cfg.ntfy_token:
            req.add_header("Authorization", f"Bearer {self.cfg.ntfy_token}")
        if self.cfg.dashboard_url:
            req.add_header("Click", self.cfg.dashboard_url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()

    def send_test(self) -> None:
        """Send one push synchronously so errors surface to the caller."""
        if not self.cfg.ntfy_topic:
            raise RuntimeError("NTFY_TOPIC is not set; run `python -m titan init` first")
        self._post("imperial-titan is connected",
                   "Test notification. Alerts from your network will arrive here.",
                   "medium", "test")
