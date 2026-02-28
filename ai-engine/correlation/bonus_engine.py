"""
Correlation bonus engine (SRS 6.3 extension).
Applies deterministic multi-stage attack chain bonuses to incident risk scores.

Extracted from main.py to keep the pipeline orchestrator thin and
make bonus logic independently testable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_WEIGHTS_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "weights.yaml"


def load_correlation_bonus(config_path: Path | None = None) -> float:
    """
    Load the deterministic correlation bonus from config/weights.yaml.
    Falls back to 15.0 if the file or key is missing/invalid.
    """
    path = config_path or _WEIGHTS_CONFIG_PATH
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return 15.0
    value = data.get("correlation_bonus", 15.0)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 15.0


def apply_correlation_bonuses(
    incidents: list[dict[str, Any]],
    correlation_bonus: float,
) -> list[dict[str, Any]]:
    """
    Apply deterministic multi-stage correlation bonuses to each incident.

    Mutates each incident dict in-place, adding:
      - incident["incident_risk_score"]  (float, 0-100)
      - incident["scoring_breakdown"]["correlation_bonus_component"]  (if bonus > 0)

    Args:
        incidents: List of incident dicts from correlate_incidents().
                   Each must have an "alerts" list whose items carry "risk_score"
                   and "scoring_breakdown".
        correlation_bonus: Base bonus unit loaded from config/weights.yaml.

    Returns:
        The same list (mutated in-place) for convenience.
    """
    for inc in incidents:
        inc_alerts = inc.get("alerts", [])
        base_risk_score = max(
            (a.get("risk_score", 0) for a in inc_alerts), default=0.0
        )
        breakdown = inc_alerts[0].get("scoring_breakdown") if inc_alerts else None

        incident_risk_score = base_risk_score

        if inc_alerts and correlation_bonus > 0:
            alert_names = {a.get("alert_name") for a in inc_alerts}

            has_ps_win   = "InsightOps \u2013 Password Spraying (Windows)" in alert_names
            has_ps_linux = "InsightOps \u2013 Password Spraying (Linux)"  in alert_names
            has_ps       = has_ps_win or has_ps_linux
            has_kb       = "InsightOps \u2013 Kerberoasting (Windows)"    in alert_names
            has_lm_win   = "InsightOps \u2013 Lateral Movement (Windows)" in alert_names
            has_lm_linux = "InsightOps \u2013 Lateral Movement (Linux)"   in alert_names
            has_lm       = has_lm_win or has_lm_linux
            has_pe_win   = "InsightOps \u2013 Privilege Escalation (Windows)" in alert_names
            has_pe_linux = "InsightOps \u2013 Privilege Escalation (Linux)"   in alert_names
            has_persist_win   = "InsightOps \u2013 Persistence (Windows)"           in alert_names
            has_persist_linux = "InsightOps \u2013 Persistence (Linux)"             in alert_names
            has_rw_win   = "InsightOps \u2013 Ransomware Pre-Impact (Windows)" in alert_names
            has_rw_linux = "InsightOps \u2013 Ransomware Pre-Impact (Linux)"   in alert_names
            has_cd_win   = "InsightOps \u2013 Credential Dumping (Windows)"    in alert_names
            has_cd_linux = "InsightOps \u2013 Credential Dumping (Linux)"      in alert_names

            has_cred_access  = has_ps or has_kb
            has_any_priv_esc = has_pe_win or has_pe_linux
            has_persistence  = has_persist_win or has_persist_linux
            has_rw_pre       = has_rw_win or has_rw_linux
            has_cd_any       = has_cd_win or has_cd_linux

            total_bonus = 0.0

            # MEDIUM: any password spraying activity
            if has_ps:
                total_bonus += correlation_bonus * 0.5

            # Password Spraying followed by Kerberoasting
            if has_ps and has_kb:
                total_bonus += correlation_bonus

            # HIGH: chain culminates in privilege escalation
            if has_pe_win and (has_ps or has_kb or has_lm):
                total_bonus += correlation_bonus
            if has_pe_linux and (has_ps or has_kb or has_lm):
                total_bonus += correlation_bonus

            # VERY_HIGH: persistence established after priv-esc or cred access
            if has_persistence and (has_any_priv_esc or has_cred_access):
                total_bonus += correlation_bonus

            # MAX: ransomware pre-impact after priv-esc, persistence, or LM
            if has_rw_pre and (has_any_priv_esc or has_persistence or has_lm):
                total_bonus += 100.0

            # VERY_HIGH: any credential dumping
            if has_cd_any:
                total_bonus += correlation_bonus
                # Additional bonus if CD follows initial access or movement
                if has_ps or has_kb or has_lm:
                    total_bonus += correlation_bonus

            # VERY_HIGH: Linux lateral movement
            if has_lm_linux:
                total_bonus += correlation_bonus
                # Amplify if cred access, CD, or priv-esc also present
                if has_cred_access or has_any_priv_esc or has_cd_any:
                    total_bonus += correlation_bonus

            if total_bonus > 0:
                incident_risk_score = min(100.0, base_risk_score + total_bonus)
                breakdown = dict(breakdown) if breakdown is not None else {}
                breakdown["correlation_bonus_component"] = round(total_bonus, 2)

        inc["incident_risk_score"] = incident_risk_score
        inc["_scoring_breakdown"]  = breakdown  # carry forward for explain step

    return incidents
