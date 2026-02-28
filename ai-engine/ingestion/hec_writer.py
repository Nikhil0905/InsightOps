"""
Write enriched incidents to Splunk via HTTP Event Collector (SRS 6).
SOC-assist only; no automated response.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import requests
import yaml

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "splunk.yaml"


def _load_config(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or CONFIG_PATH
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return data


def write_incident_to_hec(
    enriched_incident: dict[str, Any],
    config_path: Path | None = None,
) -> bool:
    """
    Send a single enriched incident to Splunk HEC.
    Returns True on success, False on failure (fail-safe).
    """
    try:
        cfg = _load_config(config_path)
        import os
        host = cfg.get("splunk_host")
        hec_port = cfg.get("hec_port", 8088)
        token = os.environ.get("SPLUNK_HEC_TOKEN") or cfg.get("token_placeholder")
        if not host or not token:
            return False
        url = f"https://{host}:{hec_port}/services/collector/event"
        payload = {
            "event": enriched_incident,
            "index": "ai_soc",
            "sourcetype": "ai:soc:incident",
            "source": "insightops:ai-engine",
        }
        headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }
        resp = requests.post(url, json=payload, headers=headers, verify=False, timeout=5)
        if resp.status_code != 200:
            logger.warning("HEC write failed: HTTP %s for incident %s", resp.status_code, enriched_incident.get("incident_id"))
            return False
        try:
            body = resp.json()
            if body.get("code", 0) != 0:
                logger.warning("HEC write failed: response code %s for incident %s", body.get("code"), enriched_incident.get("incident_id"))
                return False
        except Exception:
            pass
        logger.debug("HEC response: %s", resp.text)
        logger.debug("Wrote incident %s to Splunk HEC successfully", enriched_incident.get("incident_id"))
        return True
    except Exception:
        return False
