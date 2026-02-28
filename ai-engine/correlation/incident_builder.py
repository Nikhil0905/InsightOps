"""
Incident correlation logic (SRS 6.3).
Groups alerts by user, host, and time window to construct multi-stage attack incidents.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

# Default time window for correlation (minutes)
DEFAULT_TIME_WINDOW_MINUTES = 30


def correlate_incidents(
    alerts: list[dict[str, Any]],
    time_window_minutes: int = DEFAULT_TIME_WINDOW_MINUTES,
) -> list[dict[str, Any]]:
    """
    Correlate alerts into incidents by user, host, and time window.
    
    Args:
        alerts: List of alert dicts with keys: alert_id, user, host, timestamp
        time_window_minutes: Time window for correlation (default 30 minutes)
    
    Returns:
        List of incident dicts with keys: incident_id, alerts, chain_length, user, host, time_range
    """
    if not alerts:
        return []
    
    # Group alerts by (user, host) pairs
    groups: dict[tuple[str | None, str | None], list[dict[str, Any]]] = {}
    
    for alert in alerts:
        user = alert.get("user")
        host = alert.get("host")
        key = (user, host)
        if key not in groups:
            groups[key] = []
        groups[key].append(alert)
    
    incidents = []
    
    # Process each (user, host) group
    for (user, host), group_alerts in groups.items():
        # Sort by timestamp
        sorted_alerts = sorted(
            group_alerts,
            key=lambda a: _parse_timestamp(a.get("timestamp")),
        )
        
        # Cluster by time window
        clusters = _cluster_by_time_window(sorted_alerts, time_window_minutes)
        
        # Create incident for each cluster
        for cluster in clusters:
            incident = {
                "incident_id": str(uuid.uuid4()),
                "alerts": cluster,
                "chain_length": len(cluster),
                "user": user,
                "host": host,
                "time_range": {
                    "start": cluster[0].get("timestamp"),
                    "end": cluster[-1].get("timestamp"),
                },
            }
            incidents.append(incident)
    
    return incidents


def _parse_timestamp(ts: Any) -> datetime:
    """Parse timestamp string to datetime. Returns epoch if parsing fails."""
    if ts is None:
        return datetime.fromtimestamp(0)
    
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts))
    
    if isinstance(ts, str):
        # Try common formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        # Try epoch string
        try:
            return datetime.fromtimestamp(float(ts))
        except (ValueError, TypeError):
            pass
    
    return datetime.fromtimestamp(0)


def _cluster_by_time_window(
    alerts: list[dict[str, Any]],
    window_minutes: int,
) -> list[list[dict[str, Any]]]:
    """
    Cluster alerts into groups where consecutive alerts are within time window.
    """
    if not alerts:
        return []
    
    clusters: list[list[dict[str, Any]]] = []
    current_cluster: list[dict[str, Any]] = [alerts[0]]
    
    for i in range(1, len(alerts)):
        prev_time = _parse_timestamp(alerts[i - 1].get("timestamp"))
        curr_time = _parse_timestamp(alerts[i].get("timestamp"))
        time_diff = (curr_time - prev_time).total_seconds() / 60.0
        
        if time_diff <= window_minutes:
            # Within window, add to current cluster
            current_cluster.append(alerts[i])
        else:
            # Outside window, start new cluster
            clusters.append(current_cluster)
            current_cluster = [alerts[i]]
    
    # Add final cluster
    if current_cluster:
        clusters.append(current_cluster)
    
    return clusters
