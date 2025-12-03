# ─────────────────────────────────────────────────────────────
# Umbra | Trident Division
# Proprietary & Confidential – All Rights Reserved
# Unauthorized use, copying, or redistribution is strictly prohibited.
# See LICENSE for full terms.
# ─────────────────────────────────────────────────────────────

"""
framework_mapper.py

Given a normalized alert object, this module generates response guidance
mapped into multiple cybersecurity frameworks:

- NIST Incident Response (SP 800-61)
- MITRE ATT&CK
- MITRE D3FEND (defensive techniques)
- NIST Cybersecurity Framework (CSF)
- CIS Controls v8

This is deliberately heuristic and compact: it uses alert fields like
log_type, severity, tags, and mitre technique IDs to produce structured
but human-readable guidance.

Expected alert structure (from alert_builder / detection_engine):

alert = {
    "rule_id": str,
    "rule_name": str,
    "description": str,
    "severity": "low" | "medium" | "high" | "critical",
    "log_type": "auth" | "network" | "endpoint" | "exfiltration",
    "source": "scenario" | "threat_intel",
    "tags": [str, ...],
    "mitre": [str, ...],  # e.g. ["T1041", "T1078"]
    ...
}

The main entry point is:

    map_alert_to_frameworks(alert: dict) -> dict

which returns:

{
    "nist_ir": {...},
    "mitre_attck": {...},
    "mitre_d3fend": {...},
    "nist_csf": {...},
    "cis_controls": {...}
}
"""

from typing import Dict, List, Any


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _has_tag(alert: Dict[str, Any], keyword: str) -> bool:
    tags = alert.get("tags") or []
    keyword_l = keyword.lower()
    return any(isinstance(t, str) and keyword_l in t.lower() for t in tags)


def _severity_bucket(alert: Dict[str, Any]) -> str:
    sev = (alert.get("severity") or "").lower()
    if sev not in ("low", "medium", "high", "critical"):
        return "medium"
    return sev


def _log_type(alert: Dict[str, Any]) -> str:
    lt = (alert.get("log_type") or "").lower()
    if lt not in ("auth", "network", "endpoint", "exfiltration"):
        return "unknown"
    return lt


def _get_mitre_ids(alert: Dict[str, Any]) -> List[str]:
    mitre = alert.get("mitre") or []
    # Normalize and keep only TXXXX-type tokens
    result = []
    for m in mitre:
        if isinstance(m, str) and m.upper().startswith("T"):
            result.append(m.upper())
    return result


# ─────────────────────────────────────────────────────────────
# NIST Incident Response (SP 800-61)
# ─────────────────────────────────────────────────────────────

def map_nist_ir(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a NIST 800-61 style response summary.
    """
    sev = _severity_bucket(alert)
    log_type = _log_type(alert)

    # Very simple heuristic classification by log_type + tags
    if log_type == "exfiltration" or _has_tag(alert, "exfiltration"):
        category = "Potential Data Exfiltration"
    elif log_type == "auth":
        category = "Authentication / Account Misuse"
    elif log_type == "endpoint":
        category = "Endpoint / Malware / Persistence"
    elif log_type == "network":
        category = "Network Intrusion / C2 / Reconnaissance"
    else:
        category = "Suspicious Activity"

    # Detection & Analysis summary
    summary = (
        f"Umbra detected a {sev} severity event in the category: {category}. "
        f"Rule: {alert.get('rule_name') or 'Unnamed Rule'}."
    )

    # Containment / Eradication / Recovery are generic templates,
    # specialized slightly per log_type.
    containment: List[str] = []
    eradication: List[str] = []
    recovery: List[str] = []

    if log_type == "auth":
        containment = [
            "Temporarily disable or lock the affected account(s).",
            "Require password reset and re-enrollment of MFA where applicable.",
        ]
        eradication = [
            "Scan for evidence of lateral movement from this account.",
            "Remove any unauthorized access tokens or sessions.",
        ]
        recovery = [
            "Re-enable account only after investigation is complete.",
            "Increase monitoring on the account for a defined period.",
        ]
    elif log_type == "endpoint":
        containment = [
            "Isolate the endpoint from the network (NAC, EDR, or manual disconnect).",
            "Restrict access to sensitive resources from the affected host.",
        ]
        eradication = [
            "Perform full malware and EDR scan.",
            "Remove or remediate any malicious binaries, scripts, or persistence mechanisms.",
        ]
        recovery = [
            "Rebuild or restore the endpoint from a clean image if needed.",
            "Verify all patches and security tools are up-to-date before reconnecting.",
        ]
    elif log_type == "network":
        containment = [
            "Block suspicious IPs, domains, or ports at the firewall or edge.",
            "Tighten egress filtering for the involved segment.",
        ]
        eradication = [
            "Hunt for additional connections to the same destination or pattern.",
            "Remove any unauthorized tunnels, VPNs, or proxy configurations.",
        ]
        recovery = [
            "Validate that normal traffic patterns resume.",
            "Update firewall rulesets and detection signatures as needed.",
        ]
    elif log_type == "exfiltration":
        containment = [
            "Block the identified exfiltration destination(s) immediately.",
            "Suspend any associated data transfer jobs or automated tasks.",
        ]
        eradication = [
            "Identify the source of the exfiltration and remove malicious tools or scripts.",
            "Revoke any compromised credentials used during the event.",
        ]
        recovery = [
            "Restore any corrupted or tampered data from backups if required.",
            "Implement stricter data loss prevention (DLP) and egress monitoring.",
        ]
    else:
        containment = [
            "Temporarily limit access from the affected user or host until analyzed."
        ]
        eradication = [
            "Investigate logs in depth and remove any discovered malicious artifacts."
        ]
        recovery = [
            "Reinstate normal access only once confidence in remediation is established."
        ]

    return {
        "category": category,
        "severity": sev,
        "phase": "Detection & Analysis",
        "summary": summary,
        "recommended_actions": {
            "containment": containment,
            "eradication": eradication,
            "recovery": recovery,
            "lessons_learned": [
                "Document the incident and Umbra’s detection details.",
                "Update Umbra rules or anomaly thresholds based on this case.",
                "Review whether logging coverage or access controls should be improved.",
            ],
        },
    }


# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK
# ─────────────────────────────────────────────────────────────

def map_mitre_attck(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a minimal MITRE ATT&CK mapping based on alert.mitre and log_type.
    """
    mitre_ids = _get_mitre_ids(alert)
    log_type = _log_type(alert)

    # Very lightweight tactic guess from log_type
    if log_type == "auth":
        likely_tactics = ["Initial Access", "Credential Access", "Persistence"]
    elif log_type == "endpoint":
        likely_tactics = ["Execution", "Persistence", "Privilege Escalation"]
    elif log_type == "network":
        likely_tactics = ["Command and Control", "Discovery", "Lateral Movement"]
    elif log_type == "exfiltration":
        likely_tactics = ["Exfiltration", "Impact"]
    else:
        likely_tactics = ["Execution", "Discovery"]

    return {
        "techniques": mitre_ids,
        "tactics": likely_tactics,
        "summary": (
            "This alert is associated with the following MITRE ATT&CK techniques "
            f"and likely tactics: {', '.join(likely_tactics)}."
        ),
    }


# ─────────────────────────────────────────────────────────────
# MITRE D3FEND
# ─────────────────────────────────────────────────────────────

def map_mitre_d3fend(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Suggest defensive techniques at a high level.
    """
    log_type = _log_type(alert)

    defensive_techniques: List[str] = []
    if log_type == "auth":
        defensive_techniques = [
            "Strengthen MFA and conditional access policies.",
            "Increase alerting around failed login bursts and geo-anomalies.",
            "Implement passwordless or phishing-resistant authentication where possible.",
        ]
    elif log_type == "endpoint":
        defensive_techniques = [
            "Enhance EDR visibility and blocking on script engines (PowerShell, CMD, etc.).",
            "Harden application allowlists and restrict unapproved binaries.",
            "Monitor for registry or scheduled task persistence changes.",
        ]
    elif log_type == "network":
        defensive_techniques = [
            "Tighten egress filtering on outbound traffic.",
            "Deploy DNS security and block known malicious domains.",
            "Apply network segmentation to limit lateral movement.",
        ]
    elif log_type == "exfiltration":
        defensive_techniques = [
            "Implement DLP controls on outbound channels (web, email, cloud).",
            "Flag bulk transfers and unusual destinations for review.",
            "Encrypt sensitive data at rest and in transit, and log access rigorously.",
        ]
    else:
        defensive_techniques = [
            "Improve logging coverage and baselining to better distinguish normal from abnormal behavior."
        ]

    return {
        "defensive_techniques": defensive_techniques,
        "summary": "These defensive patterns can reduce the likelihood or impact of similar events.",
    }


# ─────────────────────────────────────────────────────────────
# NIST Cybersecurity Framework (CSF)
# ─────────────────────────────────────────────────────────────

def map_nist_csf(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map the alert into NIST CSF core functions.
    """
    log_type = _log_type(alert)

    # Umbra mostly sits in Detect & Respond, but we can hint others.
    functions: List[str] = ["Detect", "Respond"]
    if log_type in ("auth", "endpoint", "network", "exfiltration"):
        functions.append("Identify")
    if log_type == "exfiltration":
        functions.append("Recover")

    return {
        "functions": list(dict.fromkeys(functions)),  # de-duplicate while preserving order
        "summary": (
            "This event primarily touches the Detect and Respond functions of the NIST CSF. "
            "Umbra helps identify abnormal activity and guide an appropriate response."
        ),
    }


# ─────────────────────────────────────────────────────────────
# CIS Controls v8
# ─────────────────────────────────────────────────────────────

def map_cis_controls(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Provide a minimal CIS Controls v8 mapping.
    """
    log_type = _log_type(alert)

    controls: List[str] = []

    if log_type == "auth":
        controls = [
            "CIS 5 – Account Management",
            "CIS 6 – Access Control Management",
            "CIS 8 – Audit Log Management",
            "CIS 16 – Incident Response Management",
        ]
    elif log_type == "endpoint":
        controls = [
            "CIS 4 – Secure Configuration of Enterprise Assets",
            "CIS 10 – Malware Defenses",
            "CIS 13 – Network Monitoring and Defense",
            "CIS 16 – Incident Response Management",
        ]
    elif log_type == "network":
        controls = [
            "CIS 12 – Network Infrastructure Management",
            "CIS 13 – Network Monitoring and Defense",
            "CIS 8 – Audit Log Management",
            "CIS 16 – Incident Response Management",
        ]
    elif log_type == "exfiltration":
        controls = [
            "CIS 3 – Data Protection",
            "CIS 8 – Audit Log Management",
            "CIS 13 – Network Monitoring and Defense",
            "CIS 16 – Incident Response Management",
        ]
    else:
        controls = [
            "CIS 8 – Audit Log Management",
            "CIS 16 – Incident Response Management",
        ]

    return {
        "controls": controls,
        "summary": (
            "Hardening these CIS Controls helps reduce the likelihood and impact "
            "of similar events in the future."
        ),
    }


# ─────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────

def map_alert_to_frameworks(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    High-level function used by Umbra to attach framework-aware guidance
    to a single alert.

    Returns a dictionary that can be embedded into the alert object:
    {
        "nist_ir": {...},
        "mitre_attck": {...},
        "mitre_d3fend": {...},
        "nist_csf": {...},
        "cis_controls": {...}
    }
    """
    return {
        "nist_ir": map_nist_ir(alert),
        "mitre_attck": map_mitre_attck(alert),
        "mitre_d3fend": map_mitre_d3fend(alert),
        "nist_csf": map_nist_csf(alert),
        "cis_controls": map_cis_controls(alert),
    }
