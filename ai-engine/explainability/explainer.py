"""
Explainability logic (SRS 6.4).
Generates human-readable explanations, MITRE ATT&CK mapping, and investigation steps.
No probabilities, ML confidence, or response actions.
"""

from __future__ import annotations

from typing import Any

# MITRE ATT&CK technique mappings based on alert patterns
MITRE_TECHNIQUES: dict[str, list[str]] = {
    "ssh_brute_force": ["T1110.001", "Brute Force: Password Guessing"],
    "password_spraying": ["T1110.003", "Brute Force: Password Spraying"],
    "kerberoasting": ["T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"],
    "lateral_movement": ["T1021", "Remote Services"],
    "lateral_movement_linux": ["T1021.004", "Remote Services: SSH"],
    "privilege_escalation": ["T1068", "Exploitation for Privilege Escalation"],
    "linux_privilege_escalation": ["T1548.003", "Abuse Elevation Control Mechanism: sudo and SUID"],
    "persistence_windows": ["T1547", "Boot or Logon Autostart Execution"],
    "persistence_linux": ["T1053.003", "Scheduled Task/Job: Cron"],
    "authentication_failure": ["T1078", "Valid Accounts"],
    "privilege_change": ["T1078", "Valid Accounts"],
    "process_creation": ["T1055", "Process Injection"],
    "credential_dumping": ["T1003", "OS Credential Dumping"],
}


def explain_incident(
    incident: dict[str, Any],
    risk_score: float,
    scoring_breakdown: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Generate explainability for an incident.
    
    Args:
        incident: Incident dict with keys: incident_id, alerts, chain_length, user, host
        risk_score: Risk score (0-100)
        scoring_breakdown: Optional scoring breakdown dict
    
    Returns:
        {
            "plain_english_summary": str,
            "mitre_techniques": list[dict],
            "risk_score_explanation": str,
            "investigation_steps": list[str]
        }
    """
    alerts = incident.get("alerts", [])
    chain_length = incident.get("chain_length", 0)
    user = incident.get("user")
    host = incident.get("host")
    
    # Generate plain English summary
    summary = _generate_summary(alerts, chain_length, user, host)
    
    # Map to MITRE ATT&CK techniques
    mitre_techniques = _map_mitre_techniques(alerts)
    
    # Explain risk score
    risk_explanation = _explain_risk_score(risk_score, scoring_breakdown, alerts, chain_length)
    
    # Generate investigation steps
    investigation_steps = _generate_investigation_steps(alerts, user, host, chain_length)
    
    return {
        "plain_english_summary": summary,
        "mitre_techniques": mitre_techniques,
        "risk_score_explanation": risk_explanation,
        "investigation_steps": investigation_steps,
    }


def _generate_summary(
    alerts: list[dict[str, Any]],
    chain_length: int,
    user: str | None,
    host: str | None,
) -> str:
    """Generate plain English summary of the incident."""
    if not alerts:
        return "No alerts in incident."
    
    raw_names = [a.get("alert_name") for a in alerts]
    # Filter out None/empty values and ensure strings.
    names = [str(n) for n in raw_names if n]
    if not names:
        names = ["Unknown Alert"]
    # Preserve order while de-duplicating.
    seen: set[str] = set()
    unique_names: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            unique_names.append(n)
    
    user_str = f"user '{user}'" if user else "unknown user"
    host_str = f"host '{host}'" if host else "unknown host"
    
    if chain_length == 1:
        return (
            f"Single alert detected: {unique_names[0]} "
            f"involving {user_str} on {host_str}."
        )
    else:
        return (
            f"Multi-stage attack chain detected with {chain_length} alerts "
            f"involving {user_str} on {host_str}. "
            f"Alert types: {', '.join(unique_names[:3])}"
            + (" and others" if len(unique_names) > 3 else "")
            + "."
        )


def _map_mitre_techniques(alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Map alerts to MITRE ATT&CK techniques."""
    techniques_seen: dict[str, dict[str, str]] = {}
    
    for alert in alerts:
        alert_name = (alert.get("alert_name") or "").lower()
        
        # Pattern matching for common attack techniques
        # SSH brute force must be checked before generic password/spray patterns
        if "ssh brute force" in alert_name:
            tech_id, tech_name = MITRE_TECHNIQUES["ssh_brute_force"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
        elif "password" in alert_name or "spray" in alert_name:
            tech_id, tech_name = MITRE_TECHNIQUES["password_spraying"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
        elif "kerberoast" in alert_name or "kerberos" in alert_name:
            tech_id, tech_name = MITRE_TECHNIQUES["kerberoasting"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
        elif "lateral" in alert_name or "movement" in alert_name:
            if "linux" in alert_name:
                tech_id, tech_name = MITRE_TECHNIQUES["lateral_movement_linux"]
            else:
                tech_id, tech_name = MITRE_TECHNIQUES["lateral_movement"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
        elif "privilege" in alert_name or "escalation" in alert_name:
            # Linux privilege escalation gets a distinct technique (T1548.003)
            if "linux" in alert_name:
                tech_id, tech_name = MITRE_TECHNIQUES["linux_privilege_escalation"]
            else:
                tech_id, tech_name = MITRE_TECHNIQUES["privilege_escalation"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
        elif "persistence" in alert_name:
            if "linux" in alert_name:
                tech_id, tech_name = MITRE_TECHNIQUES["persistence_linux"]
            else:
                tech_id, tech_name = MITRE_TECHNIQUES["persistence_windows"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
        elif "authentication" in alert_name or "login" in alert_name:
            tech_id, tech_name = MITRE_TECHNIQUES["authentication_failure"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
        elif "ransomware pre-impact" in alert_name:
            techniques_seen["T1490"] = {"technique_id": "T1490", "technique_name": "Inhibit System Recovery"}
            if "linux" in alert_name:
                techniques_seen["T1083"] = {"technique_id": "T1083", "technique_name": "File and Directory Discovery"}
            else:
                techniques_seen["T1562"] = {"technique_id": "T1562", "technique_name": "Impair Defenses"}
        elif "credential dumping" in alert_name:
            tech_id, tech_name = MITRE_TECHNIQUES["credential_dumping"]
            techniques_seen[tech_id] = {"technique_id": tech_id, "technique_name": tech_name}
    
    # Default if no matches
    if not techniques_seen:
        techniques_seen["T1078"] = {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
        }
    
    return list(techniques_seen.values())


def _explain_risk_score(
    risk_score: float,
    scoring_breakdown: dict[str, Any] | None,
    alerts: list[dict[str, Any]],
    chain_length: int,
) -> str:
    """Explain why the risk score is high."""
    if risk_score >= 70:
        level = "high"
    elif risk_score >= 40:
        level = "moderate"
    else:
        level = "low"
    
    reasons = []
    
    # Check severity (numeric or string: critical/high/medium/low)
    _SEVERITY_TO_NUM = {"critical": 90, "high": 70, "medium": 45, "low": 20}
    def _severity_num(s):
        if s is None:
            return 0
        if isinstance(s, (int, float)):
            return float(s)
        return float(_SEVERITY_TO_NUM.get((s or "").lower().strip(), 0))
    if alerts:
        max_severity = max(
            (_severity_num(a.get("severity")) for a in alerts if a.get("severity") is not None),
            default=0,
        )
        if max_severity >= 70:
            reasons.append("high base severity")
        # Linux privilege escalation specific messaging
        alert_names_lower = [(a.get("alert_name") or "").lower() for a in alerts]
        if any("privilege escalation (linux" in name for name in alert_names_lower):
            reasons.append("Privilege escalation attempt on Linux host")
            reasons.append("sudo or SUID abuse indicators")
        # Persistence-specific messaging
        has_persist_win = any("persistence (windows" in name for name in alert_names_lower)
        has_persist_linux = any("persistence (linux" in name for name in alert_names_lower)
        if has_persist_win or has_persist_linux:
            reasons.append("Persistence mechanism established")
            reasons.append("Attacker attempting long-term access")
        if has_persist_win:
            reasons.append("Windows persistence via registry, startup, or scheduled task")
        if has_persist_linux:
            reasons.append("Linux persistence via cron or systemd services")
        
        has_rw_win = any("ransomware pre-impact (windows" in name for name in alert_names_lower)
        has_rw_linux = any("ransomware pre-impact (linux" in name for name in alert_names_lower)
        has_cd_win = any("credential dumping (windows" in name for name in alert_names_lower)
        has_cd_linux = any("credential dumping (linux" in name for name in alert_names_lower)
        has_lm_linux = any("lateral movement (linux" in name for name in alert_names_lower)
        
        if has_lm_linux:
            reasons.append("Linux lateral movement detected")
            reasons.append("Potential SSH fan-out or remote execution")

        if has_rw_win or has_rw_linux:
            reasons.append("Ransomware pre-impact behavior detected")
            reasons.append("Attack activity observed prior to encryption phase")
        if has_rw_win:
            reasons.append("Windows: shadow copy deletion, Defender or backup tampering")
        if has_rw_linux:
            reasons.append("Linux: service disabling, recovery inhibition, mass file discovery")

        if has_cd_win or has_cd_linux:
            reasons.append("Credential dumping activity detected")
        if has_cd_win:
            reasons.append("Possible LSASS memory access or Mimikatz-like behavior")
        if has_cd_linux:
            reasons.append("Possible /etc/shadow or sudo-based credential access")
            
    # Check chain length
    if chain_length > 1:
        reasons.append(f"multi-stage attack chain ({chain_length} alerts)")
    
    # Check scoring breakdown if available
    if scoring_breakdown:
        if scoring_breakdown.get("host_criticality_component", 0) > 20:
            reasons.append("critical host involvement")
        if scoring_breakdown.get("user_privilege_component", 0) > 20:
            reasons.append("privileged user account")
        if scoring_breakdown.get("event_frequency_component", 0) > 20:
            reasons.append("high event frequency")
        corr_bonus = scoring_breakdown.get("correlation_bonus_component", 0)
        if corr_bonus and corr_bonus > 0:
            alert_names = {a.get("alert_name") or "" for a in alerts}
            has_ps_win = "InsightOps – Password Spraying (Windows)" in alert_names
            has_ps_linux = "InsightOps – Password Spraying (Linux)" in alert_names
            has_ps = has_ps_win or has_ps_linux
            has_kb = "InsightOps – Kerberoasting (Windows)" in alert_names
            has_lm_win = "InsightOps – Lateral Movement (Windows)" in alert_names
            has_lm_linux = "InsightOps – Lateral Movement (Linux)" in alert_names
            has_lm = has_lm_win or has_lm_linux
            has_pe_win = "InsightOps – Privilege Escalation (Windows)" in alert_names
            has_pe_linux = "InsightOps – Privilege Escalation (Linux)" in alert_names
            has_persist_win = "InsightOps – Persistence (Windows)" in alert_names
            has_persist_linux = "InsightOps – Persistence (Linux)" in alert_names

            if (has_persist_win or has_persist_linux) and (has_pe_win or has_pe_linux or has_ps or has_kb):
                reasons.append("multi-stage attack culminating in persistence")
            elif (has_pe_win or has_pe_linux) and (has_ps or has_kb or has_lm):
                reasons.append("multi-stage attack culminating in privilege escalation")
            elif has_ps and has_kb:
                reasons.append(
                    "additional risk added due to multi-stage attack progression: "
                    "Password Spraying followed by Kerberoasting"
                )
            else:
                reasons.append("additional risk added due to multi-stage attack progression")
    
    if reasons:
        reason_str = ", ".join(reasons)
        return f"Risk score is {level} ({risk_score:.1f}) due to: {reason_str}."
    else:
        return f"Risk score is {level} ({risk_score:.1f})."


def _generate_investigation_steps(
    alerts: list[dict[str, Any]],
    user: str | None,
    host: str | None,
    chain_length: int,
) -> list[str]:
    """Generate suggested analyst investigation steps."""
    steps = []
    
    if user:
        steps.append(f"Review authentication logs for user '{user}'")
        steps.append(f"Check user '{user}' account status and recent activity")
    
    if host:
        steps.append(f"Examine host '{host}' for signs of compromise")
        steps.append(f"Review process execution logs on '{host}'")
    
    if chain_length > 1:
        steps.append("Analyze the attack chain progression across alerts")
        steps.append("Identify the initial entry point and lateral movement path")
    
    # Add alert-specific steps
    alert_names = [(a.get("alert_name") or "").lower() for a in alerts]
    if any("ssh brute force" in name for name in alert_names):
        steps.append(
            "Review /var/log/auth.log for repeated SSH authentication failures against a single user account"
        )
        steps.append(
            "Check source IP reputation and consider temporary firewall block if attempts are sustained"
        )
    if any("password spraying (linux" in name for name in alert_names):
        steps.append("Investigate potential SSH password spraying and pre-compromise credential access attempt")
    elif any("password" in name or "spray" in name for name in alert_names):
        steps.append("Review failed authentication attempts and account lockout events")
    if any("kerberoast" in name for name in alert_names):
        steps.append("Examine Kerberos ticket requests and service account usage")
    if any("lateral" in name for name in alert_names):
        steps.append("Review network connections and remote service access")
        if any("linux" in name for name in alert_names):
            steps.append("Investigate potential SSH fan-out or remote execution")
    if any("privilege escalation (linux" in name for name in alert_names):
        steps.append(
            "Investigate privilege escalation attempt on Linux host, focusing on sudo or SUID abuse indicators"
        )
    if any("ransomware" in name for name in alert_names):
        steps.append("Immediate containment and isolation recommended")
    
    # Default steps
    if not steps:
        steps.append("Review alert details and context")
        steps.append("Check system logs for related events")
    
    steps.append("Document findings and update incident notes")
    
    return steps
