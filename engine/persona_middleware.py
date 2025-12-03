"""
Umbra | Trident Division - Persona Middleware

This module gives Umbra a personality layer based on:
- Who is using her (Creator vs Agent)
- The severity of the alert
- The anomaly tags (zero-day, exfil, C2, etc.)

It does NOT do detection.
It only:
- Interprets context
- Generates Umbra's "voice line"
- Attaches operator info to each alert
"""

from dataclasses import dataclass
from typing import Any, Dict, List


# ---------------------------
# Identity / Context
# ---------------------------

CREATOR_NAMES = {
    "trident",
    "trident the creator",
    "trident-productions",
}


@dataclass
class UmbraContext:
    user_name: str
    is_creator: bool
    mode: str               # "creator" or "agent"
    display_name: str
    clearance_label: str    # e.g. "GOD MODE" or "BLACKSITE ACCESS – LEVEL III"


def get_umbra_context(raw_name: str) -> UmbraContext:
    """
    Build Umbra's view of the current operator.

    If the name matches a Creator alias, Umbra enters 'creator' mode ("God Mode").
    Otherwise, the operator is treated as a high-level agent.
    """
    name = (raw_name or "").strip()
    lowered = name.lower()

    if lowered in CREATOR_NAMES:
        is_creator = True
        mode = "creator"
        display_name = name if name else "Creator"
        clearance_label = "GOD MODE"
    else:
        is_creator = False
        mode = "agent"
        display_name = name if name else "Agent"
        clearance_label = "BLACKSITE ACCESS – LEVEL III"

    return UmbraContext(
        user_name=display_name,
        is_creator=is_creator,
        mode=mode,
        display_name=display_name,
        clearance_label=clearance_label,
    )


# ---------------------------
# Persona Lines (building blocks)
# ---------------------------

def _severity_line(severity: str, risk_level: str) -> str:
    sev = (severity or "").lower()
    risk = (risk_level or "").lower()

    if sev == "critical" or risk == "critical":
        return "An active adversary is present. Immediate containment is advised."

    if sev == "high" or risk == "high":
        return "This is deliberate, not accidental. Someone is probing your defenses."

    if sev == "medium" or risk == "medium":
        return "Behavioral drift detected. Not definitive, but not clean either."

    # low / default
    return "Minor deviation observed. Irritating, but mostly noise."


def _creator_overlay_line(ctx: UmbraContext) -> str:
    return (
        f"Creator {ctx.user_name} recognized. "
        "Elevating perspective to full-spectrum God Mode."
    )


def _agent_overlay_line(ctx: UmbraContext) -> str:
    return (
        f"Blacksite clearance confirmed for Agent {ctx.user_name}. "
        "You operate under Trident's shadow."
    )


def _tag_flavor_line(tags: List[str]) -> str:
    tags = [t.lower() for t in (tags or [])]

    if "zero_day_suspect" in tags:
        return "This pattern does not exist in my memory. Treat it as a potential zero-day."

    if "exfil_suspect" in tags:
        return "Data is trying to leave the environment. Quietly. That is rarely innocent."

    if "c2_suspect" in tags:
        return "Command-and-control style communication detected between this host and an external endpoint."

    if "credential_access" in tags:
        return "Credential surfaces are under pressure. If they obtain keys, everything downstream falls."

    if "behavior_deviation" in tags:
        return "The entity’s behavior has shifted away from its baseline. That is where attackers hide."

    if "insider_risk" in tags:
        return "Context suggests elevated insider risk for this operator."

    return ""


# ---------------------------
# Public API
# ---------------------------

def get_welcome_line(ctx: UmbraContext) -> str:
    """
    Return Umbra's greeting line when the UI loads.
    """
    if ctx.is_creator:
        return (
            f"Umbra online. Creator {ctx.user_name} recognized. "
            "God Mode overrides are standing by."
        )
    else:
        return (
            f"Umbra online. {ctx.clearance_label} granted to Agent {ctx.user_name}. "
            "I will watch the perimeter while you review the signal."
        )


def attach_persona_to_alert(alert: Dict[str, Any], ctx: UmbraContext) -> Dict[str, Any]:
    """
    Given an alert dict and UmbraContext, attach a persona line:

    - Uses severity and anomaly risk/tags
    - Changes slightly if the Creator is present

    Adds to alert:
    - 'umbra_voice_line': str
    - 'umbra_operator': { name, mode, clearance }
    """
    severity = alert.get("severity", "medium")
    anomaly = alert.get("anomaly", {}) or {}
    risk_level = anomaly.get("risk_level", "medium")
    tags = anomaly.get("tags", [])

    base_line = _severity_line(severity, risk_level)
    tag_line = _tag_flavor_line(tags)

    if ctx.is_creator:
        overlay = _creator_overlay_line(ctx)
    else:
        overlay = _agent_overlay_line(ctx)

    pieces = [overlay, base_line]
    if tag_line:
        pieces.append(tag_line)

    voice_line = " ".join(pieces)

    alert["umbra_voice_line"] = voice_line
    alert["umbra_operator"] = {
        "name": ctx.user_name,
        "mode": ctx.mode,
        "clearance": ctx.clearance_label,
    }
    return alert
