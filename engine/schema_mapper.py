# =======================================================================
#   © 2025 TRIDENT-PRODUCTIONS STUDIO LLC — ALL RIGHTS RESERVED
# -----------------------------------------------------------------------
#   U M B R A   |   T R I D E N T   D I V I S I O N
#   BLACKSITE THREAT INTELLIGENCE OPERATIONS PLATFORM
#
#   CLASSIFICATION: LEVEL OMEGA
#
#   Schema / dialect mapper:
#   - Detects likely log "family" (network, auth, endpoint, exfiltration,
#     email, cloud, threat_intel, unknown) from columns.
#   - Normalizes common dialects (Zeek, generic CSVs, CTI feeds, etc.)
#     into Umbra's internal canonical field names so rules + anomaly
#     engines can reason consistently.
# =======================================================================

from typing import Dict, List

import pandas as pd

SUPPORTED_LOG_FAMILIES = [
    "auth",
    "network",
    "endpoint",
    "exfiltration",
    "email",
    "cloud",
    "threat_intel",
    "infostealer",
]

CANONICAL_FIELDS: Dict[str, Dict[str, List[str]]] = {
    # 🛰 Network / flow / IDS (Zeek, Suricata, NetFlow, firewalls...)
    "network": {
        "src_ip": ["src_ip", "id.orig_h", "source_ip", "client_ip", "orig_h"],
        "dst_ip": ["dst_ip", "id.resp_h", "destination_ip", "server_ip", "resp_h"],
        "src_port": ["src_port", "id.orig_p", "sport", "source_port", "orig_p"],
        "dst_port": ["dst_port", "id.resp_p", "dport", "dest_port", "resp_p"],
        "proto": ["proto", "protocol"],
        "service": ["service", "channel", "app"],
        "bytes": ["bytes", "orig_bytes", "total_bytes"],
        "bytes_out": ["bytes_out", "resp_bytes", "out_bytes"],
        "conn_state": ["conn_state", "state"],
        "label": ["label", "detailed-label", "conn_label", "scenario_label"],
    },

    # 🔐 Authentication / identity
    "auth": {
        "user": ["user", "username", "account", "principal", "actor"],
        "status": ["status", "result", "event_type", "outcome"],
        "source_ip": ["source_ip", "src_ip", "ip", "client_ip"],
        "country": ["country", "geo", "location", "region"],
        "mfa_result": ["mfa_result", "mfa", "mfa_status"],
        "idp_name": ["idp_name", "idp", "identity_provider"],
    },

    # 💻 Endpoint / host
    "endpoint": {
        "host": ["host", "hostname", "computer", "device"],
        "user": ["user", "username", "account"],
        "process_name": ["process_name", "image", "exe", "process"],
        "pid": ["pid", "process_id"],
        "parent_process": ["parent_process", "parent_image", "parent_exe", "ppid"],
        "commandline": ["commandline", "cmdline", "process_command_line"],
        "hash": ["hash", "sha256", "sha1", "md5"],
        "memory_mb": ["memory_mb", "memory", "rss_mb"],
    },

    # 📤 Exfiltration / DLP / data movement
    "exfiltration": {
        "timestamp": ["timestamp", "time", "ts", "date"],
        "user": ["user", "username", "account"],
        "host": ["host", "hostname", "device"],
        "channel": ["channel", "service", "vector", "protocol"],
        "bytes_out": [
            "bytes_out",
            "file_size_mb",
            "file_size",
            "bytes_sent",
            "data_volume",
        ],
        "destination": ["destination", "domain", "url", "remote_host"],
        "sensitive_hits": ["sensitive_hits", "hits", "sensitivity_score"],
        "scenario_label": ["scenario_label", "label", "category", "detailed-label"],
    },

    # 📧 Email security / phishing
    "email": {
        "sender": ["sender", "from", "from_address"],
        "recipient": ["recipient", "to", "rcpt"],
        "subject": ["subject", "subj"],
        "filter_action": ["filter_action", "action", "disposition"],
        "spam_score": ["spam_score", "score"],
    },

    # ☁️ Cloud / audit
    "cloud": {
        "actor": ["actor", "user", "username", "principal", "userIdentity"],
        "action": ["action", "event_name", "eventName", "operation"],
        "resource": ["resource", "resource_name", "arn", "object"],
        "service": ["service", "event_source", "eventSource"],
        "source_ip": [
            "source_ip",
            "src_ip",
            "ip",
            "sourceIPAddress",
            "client_ip",
        ],
        "location": ["location", "region", "geo"],
        "status": ["status", "result", "outcome", "response"],
    },

    # 🧠 Threat intel / breach / CTI-like feeds
    "threat_intel": {
        "threat_type": [
            "threat_type",
            "Threat Category",
            "Predicted Threat Category",
            "Name",
            "Title",
            "Domain",
        ],
        "ioc": [
            "ioc",
            "IOCs (Indicators of Compromise)",
            "indicator",
            "Indicators",
        ],
        "threat_actor": ["threat_actor", "Threat Actor"],
        "risk_score": [
            "risk_score",
            "Severity Score",
            "Risk Level Prediction",
            "PwnCount",
        ],
        "data_classes": ["DataClasses", "data_classes"],
        "description": [
            "description",
            "Description",
            "Cleaned Threat Description",
        ],
    },

    # 🔥🆕 NEW — Infostealer credential dump schema
    "infostealer": {
        "user": ["login", "user", "username", "account"],
        "password": ["password", "pwd", "pass"],
        "source_ip": ["ip", "ip_address"],
        "domain": ["domain"],
        "url": ["url"],
        "host": ["pc", "host", "hostname", "device", "computer"],
        "os": ["os", "operating_system"],
        "path": ["path"],
        "date_compromised": ["date_compromised"],
        "date_uploaded": ["date_uploaded"],
    },
}

# -----------------------------------------------------------------------
# Infer family from column names
# -----------------------------------------------------------------------

def infer_log_families_from_columns(df: pd.DataFrame) -> List[str]:
    """
    Look at column names and guess which log family/families this CSV
    most likely belongs to.

    Returns a list like: ["network"], ["auth", "exfiltration"], or ["unknown"].
    """
    cols = {c.lower() for c in df.columns}
    families: List[str] = []

    # auth-like
    if any(c in cols for c in ("username", "user", "account")) and \
       any(c in cols for c in ("status", "result", "event_type", "login")):
        families.append("auth")

    # network-like
    if any("ip" in c for c in cols) or any(
        c in cols for c in ("src_ip", "dst_ip", "id.orig_h", "id.resp_h", "port")
    ):
        families.append("network")

    # endpoint-like
    if any(
        c in cols
        for c in ("process_name", "image", "exe", "pid", "commandline", "process")
    ):
        families.append("endpoint")

    # exfiltration-like
    if any(
        c in cols
        for c in (
            "file_size",
            "file_size_mb",
            "bytes_out",
            "bytes_sent",
            "sensitive_hits",
            "usb",
            "scenario_label",
        )
    ):
        families.append("exfiltration")

    # email-like
    if any(c in cols for c in ("sender", "recipient", "subject", "filter_action")):
        families.append("email")

    # cloud-like
    if any(
        c in cols
        for c in (
            "eventsource",
            "event_source",
            "eventname",
            "event_name",
            "resource",
            "arn",
            "cloudtrail",
        )
    ):
        families.append("cloud")

    # threat-intel-like (HIBP, CTI, breach lists)
    if any(
        c in cols
        for c in (
            "threat category",
            "iocs (indicators of compromise)",
            "threat actor",
            "pwncount",
            "dataclasses",
            "breachdate",
        )
    ):
        families.append("threat_intel")

    # 🔐 NEW: infostealer-like (your professor's CSV format)
    # source,url,login,top_logins,suggested_login,password,ip,domain,date_compromised,...
    if {"url", "login", "password", "domain", "ip"}.issubset(cols):
        families.append("infostealer")

    if not families:
        families.append("unknown")

    # De-duplicate while preserving order
    seen = set()
    final: List[str] = []
    for f in families:
        if f not in seen:
            seen.add(f)
            final.append(f)
    return final


# -----------------------------------------------------------------------
# Normalization: map dialect → Umbra canonical fields
# -----------------------------------------------------------------------

def normalize_df_for_family(df: pd.DataFrame, family: str) -> pd.DataFrame:
    """
    Return a *copy* of df with canonical Umbra fields filled in wherever
    we can map from dialect-specific column names.

    We never drop the original columns; we only add normalized ones such
    as src_ip, dst_ip, user, bytes_out, etc.
    """
    family = (family or "").lower()

    # ---------------------------------------------------------------
    # NEW: special handling for infostealer credential dumps
    # ---------------------------------------------------------------
    if family == "infostealer":
        norm_df = df.copy()
        lower_cols = {c.lower(): c for c in norm_df.columns}

        def copy_col(src: str, dst: str):
            if src in lower_cols:
                norm_df[dst] = norm_df[lower_cols[src]]

        # Map the professor CSV columns into something Umbra-ish
        copy_col("source", "stealer_log_id")
        copy_col("url", "url")
        copy_col("login", "user")
        copy_col("password", "password")
        copy_col("ip", "source_ip")
        copy_col("domain", "domain")
        copy_col("path", "process_name")
        copy_col("pc", "host")
        copy_col("os", "os")

        # Timestamp: prefer date_compromised, then date_uploaded
        ts = None
        if "date_compromised" in lower_cols:
            ts_col = lower_cols["date_compromised"]
            ts = pd.to_datetime(norm_df[ts_col], errors="coerce")
        elif "date_uploaded" in lower_cols:
            ts_col = lower_cols["date_uploaded"]
            ts = pd.to_datetime(norm_df[ts_col], errors="coerce")

        if ts is not None:
            norm_df["timestamp"] = ts

        # Give the engines a log_type + scenario to key from
        norm_df["log_type"] = "infostealer"
        if "scenario_label" not in norm_df.columns:
            norm_df["scenario_label"] = "INFOSTEALER_CREDENTIAL_EXPOSURE"

        return norm_df

    # ---------------------------------------------------------------
    # Existing generic normalization for other families
    # ---------------------------------------------------------------
    mapping = CANONICAL_FIELDS.get(family)
    if not mapping:
        # nothing to do
        return df

    norm_df = df.copy()
    lower_cols = {c.lower(): c for c in norm_df.columns}

    for canonical_name, candidates in mapping.items():
        # If canonical already exists, leave it alone
        if canonical_name in norm_df.columns:
            continue

        matched_col = None
        for candidate in candidates:
            cand_lower = candidate.lower()
            if cand_lower in lower_cols:
                matched_col = lower_cols[cand_lower]
                break

        if matched_col is not None:
            norm_df[canonical_name] = norm_df[matched_col]

    return norm_df
