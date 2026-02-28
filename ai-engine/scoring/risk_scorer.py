"""
Risk scoring logic (SRS 6.2).
Deterministic, explainable formula combining severity, host criticality,
user privilege, and event frequency to produce normalized risk score (0-100).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "weights.yaml"


def _load_weights(config_path: Path | None = None) -> dict[str, float]:
    """Load weight values from config/weights.yaml."""
    path = config_path or CONFIG_PATH
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return {
        "base_severity": float(data.get("base_severity") or 1.0),
        "host_criticality": float(data.get("host_criticality") or 1.0),
        "user_privilege": float(data.get("user_privilege") or 1.0),
        "behavioral_frequency": float(data.get("behavioral_frequency") or 1.0),
    }


def calculate_risk_score(
    severity: float,
    host_criticality: float,
    user_privilege: float,
    event_frequency: float,
    config_path: Path | None = None,
) -> dict[str, Any]:
    """
    Calculate risk score (0-100) from inputs using weighted formula.
    
    Args:
        severity: Base severity (0-100 scale)
        host_criticality: Host criticality (0-100 scale)
        user_privilege: User privilege level (0-100 scale)
        event_frequency: Event frequency indicator (0-100 scale)
        config_path: Optional path to weights.yaml
    
    Returns:
        {
            "risk_score": float (0-100),
            "scoring_breakdown": {
                "severity_component": float,
                "host_criticality_component": float,
                "user_privilege_component": float,
                "event_frequency_component": float,
                "weights": dict
            }
        }
    """
    weights = _load_weights(config_path)
    
    # Normalize inputs to 0-100 if needed (assume already normalized)
    severity_norm = max(0.0, min(100.0, float(severity)))
    host_crit_norm = max(0.0, min(100.0, float(host_criticality)))
    user_priv_norm = max(0.0, min(100.0, float(user_privilege)))
    event_freq_norm = max(0.0, min(100.0, float(event_frequency)))
    
    # Weighted components
    severity_comp = severity_norm * weights["base_severity"]
    host_crit_comp = host_crit_norm * weights["host_criticality"]
    user_priv_comp = user_priv_norm * weights["user_privilege"]
    event_freq_comp = event_freq_norm * weights["behavioral_frequency"]
    
    # Sum weighted components
    raw_score = severity_comp + host_crit_comp + user_priv_comp + event_freq_comp
    
    # Normalize to 0-100 range
    # Assume max possible raw score is sum of weights * 100
    max_possible = (
        weights["base_severity"]
        + weights["host_criticality"]
        + weights["user_privilege"]
        + weights["behavioral_frequency"]
    ) * 100.0
    
    if max_possible > 0:
        risk_score = min(100.0, (raw_score / max_possible) * 100.0)
    else:
        risk_score = 0.0
    
    return {
        "risk_score": round(risk_score, 2),
        "scoring_breakdown": {
            "severity_component": round(severity_comp, 2),
            "host_criticality_component": round(host_crit_comp, 2),
            "user_privilege_component": round(user_priv_comp, 2),
            "event_frequency_component": round(event_freq_comp, 2),
            "raw_score": round(raw_score, 2),
            "max_possible": round(max_possible, 2),
            "weights": weights,
        },
    }
