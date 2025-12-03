# ─────────────────────────────────────────────────────────────
# Umbra | Trident Division
# Proprietary & Confidential – All Rights Reserved
# Unauthorized use, copying, or redistribution is strictly prohibited.
# See LICENSE for full terms.
# ─────────────────────────────────────────────────────────────

"""
mitre_mapper.py

Central mappings between high-level threat categories Umbra detects
(e.g. infostealer, phishing, ransomware) and MITRE ATT&CK tactics
and techniques.

This is used for:
- Enriching alerts with consistent ATT&CK context
- Documentation and reporting
- Future UI views (e.g., per-threat MITRE breakdown)

Threat category examples:
    "infostealer"
    "phishing"
    "ransomware"
    "lateral_movement"
    "privilege_escalation"
    "data_exfiltration"
    "command_and_control"
    "credential_harvesting"

Main entry points:

    get_mitre_for_category(category: str) -> dict
    infer_mitre_from_alert(alert: dict) -> dict

Both return a structure like:

{
    "category": "infostealer",
    "tactics": [...],
    "techniques": [...],
    "summary": "..."
}
"""

from typing import Dict, List, Any


# ─────────────────────────────────────────────────────────────
# Core Mapping Table
# ─────────────────────────────────────────────────────────────

THREAT_TO_MITRE: Dict[str, Dict[str, Any]] = {
    "infostealer": {
        "tactics": [
            "Initial Access",
            "Credential Access",
            "Collection",
            "Exfiltration",
            "Command and Control",
        ],
        "techniques": [
            "T1555",  # Credentials from password stores
            "T1005",  # Data from local system
            "T1114",  # Email / token / mailbox data
            "T1041",  # Exfiltration over C2 channel
            "T1071",  # Application layer protocol (e.g. HTTPS)
        ],
        "summary": (
            "Infostealers focus on harvesting credentials, tokens, wallet data, and "
            "sensitive files from endpoints, then exfiltrating the data to remote "
            "command-and-control infrastructure over HTTP(S), Discord, Telegram, or "
            "similar channels."
        ),
    },
    "phishing": {
        "tactics": [
            "Initial Access",
            "Execution",
        ],
        "techniques": [
            "T1566",  # Phishing
            "T1204",  # User execution
        ],
        "summary": (
            "Phishing attacks rely on social engineering to deliver malicious links or "
            "attachments that convince users to execute payloads or disclose credentials."
        ),
    },
    "ransomware": {
        "tactics": [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Impact",
        ],
        "techniques": [
            "T1486",  # Data encrypted for impact
            "T1059",  # Command-line/script execution
            "T1078",  # Valid accounts
            "T1036",  # Masquerading
        ],
        "summary": (
            "Ransomware operators gain a foothold, escalate privileges, move laterally, "
            "and encrypt data or systems to extort payment from victims."
        ),
    },
    "lateral_movement": {
        "tactics": [
            "Lateral Movement",
            "Credential Access",
            "Discovery",
        ],
        "techniques": [
            "T1021",  # Remote services
            "T1075",  # Pass the hash (legacy)
            "T1087",  # Account discovery
        ],
        "summary": (
            "Lateral movement describes an adversary moving from one system to another "
            "inside the network using remote services, stolen credentials, or other "
            "pivot techniques."
        ),
    },
    "privilege_escalation": {
        "tactics": [
            "Privilege Escalation",
            "Defense Evasion",
        ],
        "techniques": [
            "T1068",  # Exploitation for privilege escalation
            "T1548",  # Abuse elevation control mechanism
        ],
        "summary": (
            "Privilege escalation involves abusing vulnerabilities, misconfigurations, "
            "or elevation mechanisms to gain higher privileges than initially granted."
        ),
    },
    "data_exfiltration": {
        "tactics": [
            "Collection",
            "Exfiltration",
            "Command and Control",
        ],
        "techniques": [
            "T1041",  # Exfiltration over C2 channel
            "T1048",  # Exfiltration over alternative protocol
            "T1567",  # Exfiltration over web services
        ],
        "summary": (
            "Data exfiltration focuses on staging, compressing, and transmitting "
            "sensitive data out of the environment via network channels, web "
            "services, or custom protocols."
        ),
    },
    "command_and_control": {
        "tactics": [
            "Command and Control",
        ],
        "techniques": [
            "T1071",  # Application layer protocol
            "T1095",  # Non-application layer protocol
            "T1105",  # Ingress tool transfer
        ],
        "summary": (
            "Command and control (C2) channels allow attackers to remotely control "
            "compromised systems, exfiltrate data, and deliver additional payloads."
        ),
    },
    "credential_harvesting": {
        "tactics": [
            "Credential Access",
        ],
        "techniques": [
            "T1110",  # Brute force
            "T1552",  # Unsecured credentials
            "T1555",  # Credentials from password stores
        ],
        "summary": (
            "Credential harvesting aggregates various methods of collecting valid "
            "credentials, such as brute force, scraping configuration files, and "
            "reading password databases."
        ),
    },
    "zero_day_exploit": {
        "tactics": [
            "Initial Access",
            "Execution",
            "Privilege Escalation",
        ],
        "techniques": [
            "T1203",  # Exploitation for client execution
            "T1068",  # Exploitation for privilege escalation
        ],
        "summary": (
            "Zero-day exploitation uses previously unknown or unpatched vulnerabilities "
            "to gain execution or elevated privileges on target systems."
        ),
    },
}


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def get_mitre_for_category(category: str) -> Dict[str, Any]:
    """
    Return MITRE ATT&CK metadata for a given high-level threat category.

    If the category is unknown, a minimal structure is returned.
    """
    key = (category or "").lower()
    if key in THREAT_TO_MITRE:
        entry = THREAT_TO_MITRE[key].copy()
        entry["category"] = key
        return entry

    return {
        "category": key or "unknown",
        "tactics": [],
        "techniques": [],
        "summary": "No specific MITRE mapping is defined for this category.",
    }


def infer_mitre_from_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Best-effort helper to derive a MITRE mapping from an alert object
    based on its tags. This does not replace the per-alert mapping used
    by framework_mapper, but complements it by giving a category-centric
    view suitable for reports or dashboards.
    """
    tags = [t.lower() for t in (alert.get("tags") or []) if isinstance(t, str)]

    # Simple priority-based category detection
    if "infostealer" in tags:
        return get_mitre_for_category("infostealer")
    if "phishing" in tags:
        return get_mitre_for_category("phishing")
    if "ransomware" in tags:
        return get_mitre_for_category("ransomware")
    if "lateral_movement" in tags or "lateral-movement" in tags:
        return get_mitre_for_category("lateral_movement")
    if "priv_esc" in tags or "privilege_escalation" in tags:
        return get_mitre_for_category("privilege_escalation")
    if "exfiltration" in tags or "data_exfiltration" in tags:
        return get_mitre_for_category("data_exfiltration")
    if "c2" in tags or "command_and_control" in tags:
        return get_mitre_for_category("command_and_control")
    if "credential_access" in tags or "credential_harvesting" in tags:
        return get_mitre_for_category("credential_harvesting")
    if "zero_day" in tags or "zero-day" in tags:
        return get_mitre_for_category("zero_day_exploit")

    # Fall back to empty mapping
    return get_mitre_for_category("unknown")
