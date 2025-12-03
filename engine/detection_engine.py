# ─────────────────────────────────────────────────────────────
# Umbra | Trident Division
# Proprietary & Confidential – All Rights Reserved
# Unauthorized use, copying, or redistribution is strictly prohibited.
# See LICENSE for full terms.
# ─────────────────────────────────────────────────────────────

"""
detection_engine.py

This module loads rule packs (scenario rules + threat intel rules),
applies them to log events, and returns a list of rule matches.

Rule files are expected in the /rules directory and may include:
- auth_rules.json
- network_rules.json
- endpoint_rules.json
- exfiltration_rules.json
- threat_intel_auth.json
- threat_intel_network.json
- threat_intel_endpoint.json
- threat_intel_exfiltration.json
- infostealer_rules.json
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pandas as pd

# Map each log type to the rule JSON files it should load.
# We merge "scenario" rules and "threat_intel" rules here.
RULE_FILES_BY_TYPE = {
    "auth": [
        "auth_rules.json",
        "threat_intel_auth.json",
    ],
    "network": [
        "network_rules.json",
        "threat_intel_network.json",
    ],
    "endpoint": [
        "endpoint_rules.json",
        "threat_intel_endpoint.json",
    ],
    "exfiltration": [
        "exfiltration_rules.json",
        "threat_intel_exfiltration.json",
    ],
    "email": [
        "email_rules.json",
    ],
    "cloud": [
        "cloud_rules.json",
    ],
    "threat_intel": [
        "threat_intel_rules.json",
    ],
}


# ─────────────────────────────────────────────────────────────
# Rule loading helpers
# ─────────────────────────────────────────────────────────────

def _load_json_file(path: Path) -> List[Dict[str, Any]]:
    """
    Safely load a JSON rule file.

    Returns [] if the file is missing or invalid so detection
    never crashes just because one file is bad.
    """
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        # If a rule pack comes as {"rules": [...]}, support that too.
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            return data["rules"]
        return []
    except Exception:
        # For safety: don't break detection if a file is malformed.
        return []


def _load_rules_by_filenames(rules_dir: Path, file_names: List[str]) -> List[Dict[str, Any]]:
    """Load all rules from the given list of filenames under rules_dir."""
    all_rules: List[Dict[str, Any]] = []

    for file_name in file_names:
        file_path = rules_dir / file_name
        file_rules = _load_json_file(file_path)
        all_rules.extend(file_rules)

    return all_rules


def load_rules_for_type(rules_dir: Path, log_type: str) -> List[Dict[str, Any]]:
    """
    Load all rules for a given log_type from the rules directory.

    log_type should normally be one of:
    - "auth", "network", "endpoint", "exfiltration"

    If an unknown type is provided, this returns [].
    """
    log_type_norm = (log_type or "").lower()
    file_names = RULE_FILES_BY_TYPE.get(log_type_norm, [])
    return _load_rules_by_filenames(rules_dir, file_names)


def load_all_rules(rules_dir: Path) -> List[Dict[str, Any]]:
    """
    Load every rule file we know about (all log types).

    Useful for a future "any CSV, try all rules" mode.
    """
    seen_files: Set[str] = set()
    all_file_names: List[str] = []

    for file_list in RULE_FILES_BY_TYPE.values():
        for name in file_list:
            if name not in seen_files:
                seen_files.add(name)
                all_file_names.append(name)

    return _load_rules_by_filenames(rules_dir, all_file_names)


# ─────────────────────────────────────────────────────────────
# Condition Matching Helpers
# ─────────────────────────────────────────────────────────────

def _get_field_value(event: Dict[str, Any], field: str) -> Any:
    """Safely get a field from the event dictionary."""
    if not field:
        return None
    return event.get(field)


def _matches_condition(event: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """
    Evaluate a single condition on an event.

    Expected condition structure:
    {
      "field": "dst_ip",
      "operator": "equals",
      "value": "203.0.113.45"
    }
    """
    field = condition.get("field")
    op = condition.get("operator")
    target_value = condition.get("value")

    value = _get_field_value(event, field)

    # Normalize
    if isinstance(value, str):
        value_norm = value.lower()
    else:
        value_norm = value

    if isinstance(target_value, str):
        target_norm = target_value.lower()
    else:
        target_norm = target_value

    # Basic operators
    if op == "equals":
        return value_norm == target_norm

    if op == "not_equals":
        return value_norm != target_norm

    if op == "greater_than":
        try:
            return float(value_norm) > float(target_norm)
        except Exception:
            return False

    if op == "less_than":
        try:
            return float(value_norm) < float(target_norm)
        except Exception:
            return False

    if op == "in":
        # value is in a list of allowed/target values
        if isinstance(target_value, list):
            if isinstance(value_norm, str):
                return value_norm in [str(v).lower() for v in target_value]
            return value_norm in target_value
        return False

    if op == "not_in":
        if isinstance(target_value, list):
            if isinstance(value_norm, str):
                return value_norm not in [str(v).lower() for v in target_value]
            return value_norm not in target_value
        return False

    if op == "contains":
        # String containment
        if isinstance(value_norm, str) and isinstance(target_norm, str):
            return target_norm in value_norm
        return False

    if op == "not_contains":
        if isinstance(value_norm, str) and isinstance(target_norm, str):
            return target_norm not in value_norm
        return False

    if op == "starts_with":
        if isinstance(value_norm, str) and isinstance(target_norm, str):
            return value_norm.startswith(target_norm)
        return False

    if op == "not_starts_with":
        if isinstance(value_norm, str) and isinstance(target_norm, str):
            return not value_norm.startswith(target_norm)
        return False

    # Custom / derived-field operators like:
    # "unique_dst_ports_last_5m", "failed_count_last_10m", etc.
    # These are expected to be pre-calculated fields in the event dict.
    # So we just treat them like normal scalar comparisons above.

    return False


def _rule_matches_event(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """
    Check if all conditions of a rule match a single event.

    Rule example:
    {
      "id": "...",
      "name": "...",
      "conditions": [
        { "field": "dst_ip", "operator": "equals", "value": "203.0.113.45" },
        ...
      ]
    }
    """
    conditions = rule.get("conditions", [])

    # If no conditions, treat as non-matching to avoid noise
    if not conditions:
        return False

    for cond in conditions:
        if not _matches_condition(event, cond):
            return False

    return True


# ─────────────────────────────────────────────────────────────
# Main Detection Entry Point
# ─────────────────────────────────────────────────────────────

def run_detection(
    df: pd.DataFrame,
    log_type: Optional[str] = None,
    rules_dir: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """
    Apply all relevant rules (scenario + threat intel) to a log DataFrame.

    If log_type is one of the known domains ("auth", "network",
    "endpoint", "exfiltration"), we only load that domain's rules.

    If log_type is None or "auto", we load ALL rule files we know
    about and let each rule's own `log_type` field label the result.

    Returns a list of match objects:

    {
      "rule_id": ...,
      "rule_name": ...,
      "description": ...,
      "severity": ...,
      "log_type": ...,
      "row_index": ...,
      "source": "threat_intel" | "scenario",
      "tags": [...],
      "mitre": [...]
    }
    """
    if rules_dir is None:
        rules_dir = Path(__file__).parent / "rules"

    log_type_norm = (log_type or "").lower()

    # Decide which rules to load
    if not log_type_norm or log_type_norm == "auto":
        rules = load_all_rules(rules_dir)
    else:
        rules = load_rules_for_type(rules_dir, log_type_norm)

    matches: List[Dict[str, Any]] = []

    if df is None or df.empty or not rules:
        return matches

    # Iterate rows as dicts
    for idx, row in df.iterrows():
        event = row.to_dict()

        for rule in rules:
            try:
                if _rule_matches_event(event, rule):
                    tags = rule.get("tags", []) or []
                    tag_strings = [t.lower() for t in tags if isinstance(t, str)]
                    pack_source = "threat_intel" if "threat_intel" in tag_strings else "scenario"

                    # Prefer the rule's own log_type if present, otherwise fall back
                    match_log_type = (rule.get("log_type") or log_type_norm or "unknown").lower()

                    match = {
                        "rule_id": rule.get("id"),
                        "rule_name": rule.get("name"),
                        "description": rule.get("description"),
                        "severity": rule.get("severity", "medium"),
                        "log_type": match_log_type,
                        "row_index": idx,
                        "source": pack_source,
                        "tags": tags,
                        "mitre": rule.get("mitre", []),
                    }
                    matches.append(match)
            except Exception:
                # We never want a single bad rule to break detection.
                continue

    return matches
