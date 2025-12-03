# Umbra | Trident Division
# Proprietary Software
# Copyright © 2025 Trident-Productions Studio LLC
# All Rights Reserved.
#
# Unauthorized copying, distribution, or modification of this file,
# or any part of Umbra's architecture, is strictly prohibited.

# umbra_engine.py

UMBRA_HEADER = """
──────────────────────────────────────────────
TRIDENT DIVISION // OMEGA-BLACK CLEARANCE
ENTITY: Umbra
STATUS: OPERATIONAL
──────────────────────────────────────────────
"""

def threat_score_from_text(log_text: str) -> int:
    """
    Simple first version:
    - More 'failed' = higher score
    - 'admin' or 'root' present = higher score
    - 'new_country' or 'new location' = higher score
    """
    text = log_text.lower()

    score = 0

    # Base anomaly: any login/auth mention
    if "login" in text or "auth" in text:
        score += 10

    # Failed attempts
    failures = text.count("failed")
    score += failures * 10  # each 'failed' adds 10

    # Privileged accounts
    if "admin" in text or "root" in text:
        score += 20

    # New location hint
    if "new_country" in text or "new location" in text:
        score += 20

    # Cap between 0 and 100
    score = max(0, min(score, 100))
    return score


def severity_from_score(score: int) -> str:
    if score <= 25:
        return "LOW"
    elif score <= 50:
        return "ELEVATED"
    elif score <= 75:
        return "HIGH"
    else:
        return "CRITICAL"


def umbra_voice_line(score: int) -> str:
    """
    Mildly dramatic hybrid of Dark Analyst + Shadow Ops.
    """
    if score <= 25:
        return "Low-level anomaly noted. Logged for pattern tracking."
    elif score <= 50:
        return "Pattern formation detected. Trajectory requires attention."
    elif score <= 75:
        return (
            "Activity suggests intentional probing. "
            "Containment planning is recommended."
        )
    else:
        return (
            "Umbra has seen this escalation pattern before. "
            "It does not resolve safely. Immediate containment is advised."
        )


def build_evidence_pack(log_text: str, score: int, severity: str) -> str:
    """
    First simple Evidence Pack. We'll make this richer later.
    """
    voice = umbra_voice_line(score)

    pack = f"""{UMBRA_HEADER}

THREAT SCORE: {score}  ({severity})
Input Log Snippet:
{log_text}

Assessment:
{voice}

Recommendation:
Review the associated account, source IP, and recent access history.
"""
    return pack


def analyze_text_log(log_text: str) -> str:
    """
    Main function for Umbra right now.
    Takes a plain text description or log line, returns formatted intelligence.
    """
    score = threat_score_from_text(log_text)
    severity = severity_from_score(score)
    report = build_evidence_pack(log_text, score, severity)
    return report
