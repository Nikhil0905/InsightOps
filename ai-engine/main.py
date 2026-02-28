"""
AI-Driven SOC Intelligence Engine (SRS 6 & 7).
Execution flow: Fetch alerts -> Score -> Correlate -> Explain -> Write to Splunk HEC.
SOC-assist only. No automated response. Fail-safe if engine crashes.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any


# Add ai-engine directory so ingestion, scoring, etc. are importable
_AI_ENGINE_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _AI_ENGINE_ROOT.parent
if str(_AI_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_AI_ENGINE_ROOT))

from correlation.incident_builder import correlate_incidents
from correlation.bonus_engine import apply_correlation_bonuses, load_correlation_bonus
from explainability.explainer import explain_incident
from ingestion.hec_writer import write_incident_to_hec
from ingestion.splunk_client import fetch_alerts
from scoring.risk_scorer import calculate_risk_score
from health.signal_health import run_signal_health_check

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Defaults for scoring when alert lacks enrichment (SOC-assist; no ML)
DEFAULT_HOST_CRITICALITY = 50.0
DEFAULT_USER_PRIVILEGE = 50.0


def _severity_to_100(severity: Any) -> float:
    """Normalize severity to 0-100 scale."""
    if severity is None:
        return 50.0
    if isinstance(severity, (int, float)):
        return max(0.0, min(100.0, float(severity)))
    s = str(severity).upper()
    if s in ("CRITICAL", "CRIT"):
        return 100.0
    if s in ("HIGH", "HIGHEST"):
        return 75.0
    if s in ("MEDIUM", "MED", "MODERATE"):
        return 50.0
    if s in ("LOW", "LOWEST", "INFO"):
        return 25.0
    return 50.0


def _event_frequency_for_alerts(alerts: list[dict[str, Any]]) -> dict[tuple[str | None, str | None], float]:
    """Compute event frequency (0-100) per (user, host) from alert count in batch."""
    counts: dict[tuple[str | None, str | None], int] = {}
    for a in alerts:
        k = (a.get("user"), a.get("host"))
        counts[k] = counts.get(k, 0) + 1
    return {k: min(100.0, count * 25.0) for k, count in counts.items()}


def run_pipeline(config_path: Path | None = None, dry_run: bool = False) -> None:
    """
    Run full pipeline: fetch -> score -> correlate -> explain -> HEC.
    Fail-safe: exceptions are logged; SIEM operations are unaffected.
    When dry_run is True: do not send data to Splunk; print enriched incidents to console.
    """
    try:
        if dry_run:
            logger.info("Dry run enabled: no data will be sent to Splunk")
        # 0. Signal health check — verify telemetry freshness before processing
        run_signal_health_check(config_path=config_path)
        # 1. Fetch alerts from Splunk
        logger.info("Fetching alerts from Splunk")
        result = fetch_alerts(config_path=config_path)
        alerts = result.get("alerts", [])
        if not alerts:
            logger.info("No alerts to process")
            return

        # 2. Score alerts
        freq_map = _event_frequency_for_alerts(alerts)
        for a in alerts:
            severity = _severity_to_100(a.get("severity"))
            host_crit = DEFAULT_HOST_CRITICALITY
            user_priv = DEFAULT_USER_PRIVILEGE
            freq = freq_map.get((a.get("user"), a.get("host")), 25.0)
            score_result = calculate_risk_score(
                severity=severity,
                host_criticality=host_crit,
                user_privilege=user_priv,
                event_frequency=freq,
                config_path=None,
            )
            a["risk_score"] = score_result["risk_score"]
            a["scoring_breakdown"] = score_result["scoring_breakdown"]

        # 3. Correlate into incidents
        logger.info("Correlating incidents")
        incidents = correlate_incidents(alerts)

        # 4. Apply deterministic multi-stage correlation bonuses
        correlation_bonus = load_correlation_bonus()
        apply_correlation_bonuses(incidents, correlation_bonus)

        # 5. Generate explanations and 6. Write to HEC
        for inc in incidents:
            incident_risk_score = inc.get("incident_risk_score", 0.0)
            breakdown = inc.get("_scoring_breakdown")
            explanation = explain_incident(inc, incident_risk_score, breakdown)
            enriched = {
                "incident_id": inc.get("incident_id"),
                "chain_length": inc.get("chain_length"),
                "user": inc.get("user"),
                "host": inc.get("host"),
                "time_range": inc.get("time_range"),
                "risk_score": incident_risk_score,
                "scoring_breakdown": breakdown,
                "plain_english_summary": explanation["plain_english_summary"],
                "mitre_techniques": explanation["mitre_techniques"],
                "risk_score_explanation": explanation["risk_score_explanation"],
                "investigation_steps": explanation["investigation_steps"],
                "alerts": [
                    {
                        "alert_id": a.get("alert_id"),
                        "alert_name": a.get("alert_name"),
                        "severity": a.get("severity"),
                        "timestamp": a.get("timestamp"),
                    }
                    for a in inc.get("alerts", [])
                ],
            }
            if dry_run:
                print(json.dumps(enriched, indent=2))
                print("---")
            else:
                if write_incident_to_hec(enriched, config_path=config_path):
                    logger.info("Wrote incident %s to Splunk HEC", inc.get("incident_id"))
                else:
                    logger.warning("HEC write failed for incident %s", inc.get("incident_id"))

        logger.info("Pipeline completed")
    except Exception as e:
        logger.exception("AI engine pipeline failed (fail-safe): %s", e)
        raise SystemExit(1)


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv or "-n" in sys.argv
    run_pipeline(dry_run=dry_run)
