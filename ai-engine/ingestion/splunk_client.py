"""
Splunk alert ingestion client (SRS 6.1).
Queries Splunk REST API for triggered alerts and notable events only.
Returns normalized JSON. No scoring, correlation, or explainability.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import requests
import yaml

# Suppress InsecureRequestWarning when using verify=False for Splunk self-signed SSL.
warnings.filterwarnings("ignore", message="Unverified HTTPS request", module="urllib3")

# Log Event action alert artifacts (single-line signals), not notable/metadata.
DEFAULT_ALERTS_SPL = (
    'search index=main '
    '(source="alert:InsightOps – Password Spraying (Windows)" '
    'OR source="alert:InsightOps – Password Spraying (Linux)" '
    'OR source="alert:InsightOps – Kerberoasting (Windows)" '
    'OR source="alert:InsightOps – Lateral Movement (Windows)" '
    'OR source="alert:InsightOps – Lateral Movement (Linux)" '
    'OR source="alert:InsightOps – Privilege Escalation (Windows)" '
    'OR source="alert:InsightOps – Privilege Escalation (Linux)" '
    'OR source="alert:InsightOps – Persistence (Windows)" '
    'OR source="alert:InsightOps – Persistence (Linux)" '
    'OR source="alert:InsightOps – Ransomware Pre-Impact (Windows)" '
    'OR source="alert:InsightOps – Ransomware Pre-Impact (Linux)" '
    'OR source="alert:InsightOps – Credential Dumping (Windows)" '
    'OR source="alert:InsightOps – Credential Dumping (Linux)" '
    'OR source="alert:InsightOps – SSH Brute Force (Linux)") '
    'earliest=-15m'
)

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "splunk.yaml"


def _load_config(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or CONFIG_PATH
    with open(path) as f:
        data = yaml.safe_load(f)
    return data or {}


def _base_url(cfg: dict[str, Any]) -> str:
    """REST API base URL: https://host:management_port (8089 for search jobs)."""
    host = cfg.get("splunk_host") or ""
    management_port = cfg.get("management_port") or 8089
    return f"https://{host}:{management_port}"


def _auth(cfg: dict[str, Any]) -> tuple[str, str]:
    """REST API auth: username + password.

    Resolution order (first non-empty value wins):
      1. Environment variables: SPLUNK_USERNAME / SPLUNK_PASSWORD
      2. config/splunk.yaml fields: username / password
    """
    import os
    user = os.environ.get("SPLUNK_USERNAME") or cfg.get("username")
    password = os.environ.get("SPLUNK_PASSWORD") or cfg.get("password")
    if not user or not password:
        raise ValueError(
            "Splunk credentials not found. "
            "Set SPLUNK_USERNAME and SPLUNK_PASSWORD environment variables."
        )
    return (str(user), str(password))


def _alerts_spl(cfg: dict[str, Any]) -> str:
    return cfg.get("alerts_search_spl") or DEFAULT_ALERTS_SPL


def fetch_alerts(config_path: Path | None = None) -> dict[str, Any]:
    """
    Query Splunk REST API for triggered alerts and notable events only.
    Returns normalized JSON with keys: alert_id, alert_name, severity, host, user, timestamp, source_ip.
    """
    cfg = _load_config(config_path)
    base = _base_url(cfg)
    auth = _auth(cfg)

    jobs_url = f"{base}/services/search/jobs"
    payload = {
        "search": _alerts_spl(cfg),
        "exec_mode": "oneshot",
        "output_mode": "json",
    }

    # Splunk REST on 8089 uses self-signed SSL; verify=False required to avoid connection errors.
    # Bypass proxy for direct connection to Splunk host (avoid proxy 403 for internal IPs).
    resp = requests.post(
        jobs_url,
        data=payload,
        auth=auth,
        verify=False,
        timeout=300,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": None, "https": None},
    )
    resp.raise_for_status()

    raw = resp.json()
    alerts = _normalize_results(raw)
    return {"alerts": alerts}


def _alert_type_from_source(source: Any) -> tuple[str, str]:
    """Classify alert from result source. Returns (alert_name, severity)."""
    s = (source or "").strip()
    if "Credential Dumping (Windows)" in s:
        return ("InsightOps – Credential Dumping (Windows)", "critical")
    if "Credential Dumping (Linux)" in s:
        return ("InsightOps – Credential Dumping (Linux)", "critical")
    if "Ransomware Pre-Impact (Windows)" in s:
        return ("InsightOps – Ransomware Pre-Impact (Windows)", "critical")
    if "Ransomware Pre-Impact (Linux)" in s:
        return ("InsightOps – Ransomware Pre-Impact (Linux)", "critical")
    if "Privilege Escalation (Linux)" in s:
        return ("InsightOps – Privilege Escalation (Linux)", "critical")
    if "Privilege Escalation (Windows)" in s or "Privilege Escalation" in s:
        return ("InsightOps – Privilege Escalation (Windows)", "critical")
    if "Persistence (Windows)" in s:
        return ("InsightOps – Persistence (Windows)", "critical")
    if "Persistence (Linux)" in s:
        return ("InsightOps – Persistence (Linux)", "critical")
    if "Kerberoasting" in s:
        return ("InsightOps – Kerberoasting (Windows)", "critical")
    if "Lateral Movement (Linux)" in s:
        return ("InsightOps – Lateral Movement (Linux)", "high")
    if "Lateral Movement" in s:
        return ("InsightOps – Lateral Movement (Windows)", "high")
    if "SSH Brute Force (Linux)" in s:
        return ("InsightOps – SSH Brute Force (Linux)", "low")
    if "Password Spraying (Linux)" in s:
        return ("InsightOps – Password Spraying (Linux)", "high")
    if "Password Spraying" in s:
        return ("InsightOps – Password Spraying (Windows)", "high")
    return ("InsightOps – Password Spraying (Windows)", "high")


def _normalize_results(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Map Splunk result rows to minimal alert object (signal; missing fields allowed)."""
    results = raw.get("results") or raw.get("result") or []
    out = []
    for result in results:
        if not isinstance(result, dict):
            continue
        alert_name, severity = _alert_type_from_source(result.get("source"))
        alert = {
            "alert_id": result.get("sid") or result.get("_cd"),
            "alert_name": alert_name,
            "severity": severity,
            "host": result.get("host"),
            "user": _get_first(result, ("user", "src_user", "User", "Account_Name", "UserName")),
            "timestamp": result.get("_time"),
            "source_ip": _get_first(result, ("src", "src_ip", "source_ip")),
        }
        out.append(alert)
    return out


def _get_first(row: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in row and row[k] is not None:
            return row[k]
    return None
