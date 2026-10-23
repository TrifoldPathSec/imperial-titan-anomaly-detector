"""Settings, read from environment variables and an optional .env file.

Every knob has a default that works for a small home network; the README
explains what each one changes.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field, replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

SEVERITIES = ("low", "medium", "high")


def load_dotenv(path: Path = ENV_FILE) -> None:
    """Minimal KEY=VALUE loader. Real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _env(name: str, default, cast=str):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return cast(raw)


@dataclass(frozen=True)
class Config:
    db_path: Path = PROJECT_ROOT / "data" / "titan.db"

    # Baseline learning
    learning_hours: float = 72.0        # whole network: no baseline alerts before this
    device_grace_hours: float = 24.0    # a newly seen device: no new-domain alerts yet
    min_baseline_days: int = 3          # days of history needed for hour/volume checks

    # Unusual-hour detector
    rare_hour_ratio: float = 0.10       # active on fewer than 10% of days at this hour
    rare_hour_min_packets: int = 20     # outbound packets to the internet before alerting

    # Volume spike detector
    spike_sigma: float = 4.0
    spike_min_bytes: int = 50_000_000

    # Fan-out (scan) detector
    fanout_window: int = 60
    fanout_targets: int = 40

    # Domains that never alert (suffix match)
    ignore_domains: tuple[str, ...] = field(default=("local", "arpa", "lan", "home", "internal"))

    # Phone notifications (ntfy)
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ntfy_token: str = ""
    push_min_severity: str = "medium"
    push_per_10min: int = 10
    dashboard_url: str = ""

    # Dashboard
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5099

    def with_overrides(self, **kw) -> "Config":
        return replace(self, **kw)

    @classmethod
    def from_env(cls) -> "Config":
        load_dotenv()
        d = cls()
        ignore = _env("TITAN_IGNORE_DOMAINS", "")
        return cls(
            db_path=Path(_env("TITAN_DB", str(d.db_path))).expanduser(),
            learning_hours=_env("TITAN_LEARNING_HOURS", d.learning_hours, float),
            device_grace_hours=_env("TITAN_DEVICE_GRACE_HOURS", d.device_grace_hours, float),
            min_baseline_days=_env("TITAN_MIN_BASELINE_DAYS", d.min_baseline_days, int),
            rare_hour_ratio=_env("TITAN_RARE_HOUR_RATIO", d.rare_hour_ratio, float),
            rare_hour_min_packets=_env("TITAN_RARE_HOUR_MIN_PACKETS", d.rare_hour_min_packets, int),
            spike_sigma=_env("TITAN_SPIKE_SIGMA", d.spike_sigma, float),
            spike_min_bytes=_env("TITAN_SPIKE_MIN_BYTES", d.spike_min_bytes, int),
            fanout_window=_env("TITAN_FANOUT_WINDOW", d.fanout_window, int),
            fanout_targets=_env("TITAN_FANOUT_TARGETS", d.fanout_targets, int),
            ignore_domains=d.ignore_domains + tuple(x.strip().lower() for x in ignore.split(",") if x.strip()),
            ntfy_server=_env("NTFY_SERVER", d.ntfy_server).rstrip("/"),
            ntfy_topic=_env("NTFY_TOPIC", d.ntfy_topic),
            ntfy_token=_env("NTFY_TOKEN", d.ntfy_token),
            push_min_severity=_env("TITAN_PUSH_MIN_SEVERITY", d.push_min_severity),
            push_per_10min=_env("TITAN_PUSH_PER_10MIN", d.push_per_10min, int),
            dashboard_url=_env("TITAN_DASHBOARD_URL", d.dashboard_url),
            dashboard_host=_env("TITAN_DASHBOARD_HOST", d.dashboard_host),
            dashboard_port=_env("TITAN_DASHBOARD_PORT", d.dashboard_port, int),
        )


def ensure_env_file() -> tuple[Path, bool]:
    """Create .env with a random, hard-to-guess ntfy topic if none exists.

    Returns (path, created). Anyone who knows an ntfy.sh topic can read it,
    so the topic name is the secret.
    """
    if ENV_FILE.exists():
        return ENV_FILE, False
    topic = "titan-" + secrets.token_urlsafe(18).replace("_", "").replace("-", "")[:22].lower()
    ENV_FILE.write_text(
        "# imperial-titan settings. This file is git-ignored: the topic is a secret.\n"
        "NTFY_SERVER=https://ntfy.sh\n"
        f"NTFY_TOPIC={topic}\n"
        "# NTFY_TOKEN=            # only for a protected or self-hosted server\n"
        "TITAN_PUSH_MIN_SEVERITY=medium\n"
        "# TITAN_DASHBOARD_URL=http://<mac-lan-ip>:5099   # tap-through link in pushes\n"
        "# TITAN_LEARNING_HOURS=72\n"
        "# TITAN_IGNORE_DOMAINS=apple.com,icloud.com\n"
    )
    ENV_FILE.chmod(0o600)
    return ENV_FILE, True
