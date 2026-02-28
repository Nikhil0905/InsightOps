"""
Signal Health Check (SOC maturity / telemetry visibility feature).

Queries Splunk for the latest event time per critical sourcetype and
prints human-readable freshness warnings to stdout.

This module does NOT create detections, incidents, or Splunk writes.
All exceptions are caught; the check is entirely fail-safe.
"""

from __future__ import annotations

import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml

warnings.filterwarnings("ignore", message="Unverified HTTPS request", module="urllib3")

_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "splunk.yaml"

# How old an event must be (minutes) before we warn.
STALE_THRESHOLD_MINUTES = 10

# Sourcetypes/sources to check, with a display label and the SPL fragment
# that identifies them inside `index=main`.
_SIGNALS: list[dict[str, str]] = [
    {
        "label": "linux_secure",
        "spl_filter": 'sourcetype=linux_secure',
    },
    {
        "label": "wineventlog:security",
        "spl_filter": '(sourcetype="wineventlog:security" OR sourcetype="XmlWinEventLog:Security")',
    },
    {
        "label": 'alert:InsightOps*',
        "spl_filter": 'source="alert:InsightOps*"',
    },
]


def _load_config(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or _CONFIG_PATH
    with open(path) as f:
        data = yaml.safe_load(f)
    return data or {}


def _base_url(cfg: dict[str, Any]) -> str:
    host = cfg.get("splunk_host") or ""
    port = cfg.get("management_port") or 8089
    return f"https://{host}:{port}"


def _auth(cfg: dict[str, Any]) -> tuple[str, str]:
    """Resolution order: env vars first, yaml fallback."""
    import os
    user = os.environ.get("SPLUNK_USERNAME") or cfg.get("username")
    password = os.environ.get("SPLUNK_PASSWORD") or cfg.get("password")
    return (str(user or ""), str(password or ""))


def _query_latest_event_time(
    base_url: str,
    auth: tuple[str, str],
    spl_filter: str,
) -> datetime | None:
    """
    Run a oneshot stats search to get the latest _time for the given filter.
    Returns a timezone-aware UTC datetime, or None if no events found or on error.
    """
    spl = f"search index=main {spl_filter} | stats latest(_time) as latest_time"
    resp = requests.post(
        f"{base_url}/services/search/jobs",
        data={"search": spl, "exec_mode": "oneshot", "output_mode": "json"},
        auth=auth,
        verify=False,
        timeout=15,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": None, "https": None},
    )
    resp.raise_for_status()
    results = resp.json().get("results") or []
    if not results:
        return None
    raw = results[0].get("latest_time")
    if not raw:
        return None
    try:
        ts = float(raw)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, TypeError):
        return None


def _check_signal(
    base_url: str,
    auth: tuple[str, str],
    signal: dict[str, str],
    now: datetime,
) -> None:
    """
    Check one signal and print its health status to stdout.
    All exceptions are caught so a single failure never aborts the check.
    """
    label = signal["label"]
    spl_filter = signal["spl_filter"]
    try:
        latest = _query_latest_event_time(base_url, auth, spl_filter)
        if latest is None:
            print(f"\u26a0\ufe0f  {label}: no events in last {STALE_THRESHOLD_MINUTES} minutes")
            return
        lag_minutes = (now - latest).total_seconds() / 60.0
        if lag_minutes > STALE_THRESHOLD_MINUTES:
            lag_rounded = int(lag_minutes)
            print(f"\u26a0\ufe0f  {label}: no events in last {lag_rounded} minutes")
        else:
            lag_rounded = max(0, int(lag_minutes))
            print(f"[OK] {label}: last event {lag_rounded} minute{'s' if lag_rounded != 1 else ''} ago")
    except Exception as exc:  # noqa: BLE001
        # Fail-safe: never crash the pipeline
        print(f"\u26a0\ufe0f  {label}: health check failed ({exc})")


def run_signal_health_check(config_path: Path | None = None) -> None:
    """
    Query Splunk for the latest event time per critical sourcetype and
    print freshness status to stdout.

    Entirely fail-safe: no exception propagates to the caller.
    Does NOT write to Splunk, raise alerts, or affect scoring/correlation.
    """
    print("--- Signal Health Check ---")
    try:
        cfg = _load_config(config_path)
        base_url = _base_url(cfg)
        auth = _auth(cfg)
        now = datetime.now(tz=timezone.utc)
        for signal in _SIGNALS:
            _check_signal(base_url, auth, signal, now)
    except Exception as exc:  # noqa: BLE001
        print(f"\u26a0\ufe0f  Signal health check unavailable: {exc}")
    finally:
        print("---------------------------")
        sys.stdout.flush()
