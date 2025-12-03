# ─────────────────────────────────────────────────────────────
# Umbra | Trident Division
# Proprietary & Confidential – All Rights Reserved
# Unauthorized use, copying, or redistribution is strictly prohibited.
# See LICENSE for full terms.
# ─────────────────────────────────────────────────────────────

"""
alert_builder.py

Takes raw match objects from the detection engine (and optionally anomaly
engine) and converts them into rich Umbra alerts, including:

- Normalized fields (id, type, severity, log_type, etc.)
- Embedded event context (selected log fields)
- Multi-framework guidance (NIST IR, MITRE ATT&CK, D3FEND, NIST CSF, CIS)

Main entry points:

    build_rule_alerts(matches: list, df: DataFrame, log_type: str) -> list[dict]

Later, you can add:

    build_anomaly_alerts(anomalies: list, df: DataFrame, log_type: str)

Each alert returned by this module is ready to be displayed in the UI.
"""

from typing import Any, Dict, List, Optional

import pandas as pd

from engine.framework_mapper import map_alert_to_frameworks


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _normalize_severity(sev: Optional[str]) -> str:
    if not sev:
        return "medium"
    sev = sev.lower()
    if sev not in ("low", "medium", "high", "critical"):
        return "medium"
    return sev


def _extract_event_context(row: pd.Series, max_fields: int = 15) -> Dict[str, Any]:
    """
    Convert a DataFrame row into a smaller dict for display.
    You can tweak which fields you keep by filtering here later.
    """
    event = row.to_dict()
    # If you want, you can limit or reorder fields here.
    if len(event) > max_fields:
        # Keep only the first N items deterministically
        trimmed = {}
        for i, (k, v) in enumerate(event.items()):
            trimmed[k] = v
            if i >= max_fields - 1:
                break
        return trimmed
    return event


def _base_alert_from_match(
    match: Dict[str, Any],
    df: pd.DataFrame,
    log_type: str,
) -> Dict[str, Any]:
    """
    Convert a single rule match + its row into a base alert dict
    (before adding frameworks).
    """
    row_index = match.get("row_index")
    if row_index is None or row_index not in df.index:
        event_context = {}
    else:
        event_context = _extract_event_context(df.loc[row_index])

    severity = _normalize_severity(match.get("severity"))
    log_type_norm = (log_type or match.get("log_type") or "").lower() or "unknown"

    # Determine human-readable source
    source_raw = (match.get("source") or "").lower()
    if source_raw == "threat_intel":
        source_label = "Threat Intel Rule"
    elif source_raw == "scenario":
        source_label = "Scenario Rule"
    else:
        source_label = "Rule Engine"

    alert_id = f"{match.get('rule_id', 'RULE')}-{row_index}"

    base_alert = {
        "id": alert_id,
        "type": "rule",  # later you can add "anomaly" etc.
        "rule_id": match.get("rule_id"),
        "rule_name": match.get("rule_name"),
        "description": match.get("description"),
        "severity": severity,
        "log_type": log_type_norm,
        "source": source_label,
        "raw_source_flag": match.get("source"),  # "scenario" | "threat_intel" | None
        "tags": match.get("tags") or [],
        "mitre": match.get("mitre") or [],
        "row_index": row_index,
        "event": event_context,
    }

    # A short message for cards / tables
    base_alert["short_message"] = (
        f"[{severity.upper()}] {base_alert['rule_name'] or 'Umbra Detection'}"
    )

    return base_alert


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def build_rule_alerts(
    matches: List[Dict[str, Any]],
    df: pd.DataFrame,
    log_type: str,
) -> List[Dict[str, Any]]:
    """
    Build a list of rich alert dicts from detection_engine matches.

    Each alert will include:
    - core fields (id, severity, type, etc.)
    - event context
    - frameworks: {...} -> NIST IR, MITRE ATT&CK, D3FEND, NIST CSF, CIS Controls
    """
    if not matches or df is None or df.empty:
        return []

    alerts: List[Dict[str, Any]] = []

    for match in matches:
        try:
            base_alert = _base_alert_from_match(match, df, log_type)
            # Attach framework-aware guidance
            base_alert["frameworks"] = map_alert_to_frameworks(base_alert)
            alerts.append(base_alert)
        except Exception:
            # Never let a single bad match break alert generation
            continue

    return alerts


# (Optional) skeleton for anomaly alerts if you expand later.
def build_anomaly_alerts(
    anomalies: List[Dict[str, Any]],
    df: pd.DataFrame,
    log_type: str,
) -> List[Dict[str, Any]]:
    """
    Placeholder for integrating anomaly_engine output into Umbra alerts.

    Expected anomaly structure (example):

    anomaly = {
        "id": str,
        "score": float,
        "reason": str,
        "row_index": int,
        "log_type": "...",
        "tags": [...],
        "mitre": [...],  # optional
    }
    """
    if not anomalies or df is None or df.empty:
        return []

    alerts: List[Dict[str, Any]] = []

    for anom in anomalies:
        try:
            row_index = anom.get("row_index")
            if row_index is None or row_index not in df.index:
                event_context = {}
            else:
                event_context = _extract_event_context(df.loc[row_index])

            severity = "high" if anom.get("score", 0) >= 0.9 else "medium"

            alert = {
                "id": anom.get("id") or f"ANOM-{row_index}",
                "type": "anomaly",
                "rule_id": None,
                "rule_name": "Umbra Anomaly Detection",
                "description": anom.get("reason") or "Umbra detected anomalous behavior.",
                "severity": severity,
                "log_type": (log_type or anom.get("log_type") or "").lower() or "unknown",
                "source": "Umbra Anomaly Engine",
                "raw_source_flag": "anomaly",
                "tags": anom.get("tags") or [],
                "mitre": anom.get("mitre") or [],
                "row_index": row_index,
                "event": event_context,
                "short_message": f"[ANOMALY-{severity.upper()}] Umbra anomaly detection",
            }

            # Add frameworks for anomaly-based alerts as well
            alert["frameworks"] = map_alert_to_frameworks(alert)
            alerts.append(alert)
        except Exception:
            continue

    return alerts
