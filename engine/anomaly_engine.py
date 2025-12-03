# ─────────────────────────────────────────────────────────────
# Umbra | Trident Division
# Proprietary & Confidential – All Rights Reserved
# Unauthorized use, copying, or redistribution is strictly prohibited.
# See LICENSE for full terms.
# ─────────────────────────────────────────────────────────────

"""
anomaly_engine.py

Umbra's "Zero-Day Brain".

Lightweight anomaly detection on log data to highlight events that
*look* suspicious even if they do not match any explicit rule.

Main entry point:

    run_anomaly_detection(df: DataFrame, log_type: str | None) -> list[dict]

It returns a list of anomaly objects:

    anomaly = {
        "id": str,
        "score": float,          # 0.0 - 1.0 anomaly confidence
        "reason": str,           # human-readable explanation
        "row_index": int,        # index into df
        "log_type": str,
        "tags": list[str],
        "mitre": list[str],      # optional ATT&CK technique IDs
    }
"""

from typing import Any, Dict, List, Optional, Sequence

import numpy as np
import pandas as pd


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _safe_numeric_series(df: pd.DataFrame, field: str) -> Optional[pd.Series]:
    """Return a numeric Series for a field if it exists, else None."""
    if field not in df.columns:
        return None
    try:
        s = pd.to_numeric(df[field], errors="coerce")
        if s.notna().sum() == 0:
            return None
        return s
    except Exception:
        return None


def _zscore_outliers(series: pd.Series, threshold: float = 3.0) -> List[int]:
    """
    Very simple z-score based outlier detection.
    Returns index labels where |z| > threshold.
    """
    s = series.dropna()
    if s.empty:
        return []

    mean = s.mean()
    std = s.std(ddof=0) or 0.0
    if std == 0.0:
        return []

    z = (s - mean) / std
    mask = z.abs() > threshold
    return list(s[mask].index)


def _percentile_outliers(series: pd.Series, low: float = 0.01, high: float = 0.99) -> List[int]:
    """
    Identify values below a low percentile or above a high percentile as outliers.
    """
    s = series.dropna()
    if s.empty:
        return []
    lo = s.quantile(low)
    hi = s.quantile(high)
    mask = (s < lo) | (s > hi)
    return list(s[mask].index)


def _ensure_unique(indices: Sequence[int]) -> List[int]:
    """Return indices in sorted unique order."""
    return sorted(set(indices))


# ─────────────────────────────────────────────────────────────
# Log-Type Specific Anomaly Heuristics
# ─────────────────────────────────────────────────────────────

def _detect_network_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []

    # Heuristic 1: Large outbound bytes compared to peers
    series = _safe_numeric_series(df, "bytes_sent") or _safe_numeric_series(df, "bytes")
    if series is not None:
        outlier_idx = _percentile_outliers(series, low=0.0, high=0.995)
        for idx in outlier_idx:
            anomalies.append({
                "id": f"ANOM-NET-LARGE-OUT-{idx}",
                "score": 0.95,
                "reason": "Large outbound transfer compared to peer traffic.",
                "row_index": idx,
                "log_type": "network",
                "tags": ["anomaly", "exfiltration_suspected"],
                "mitre": ["T1041"],  # Exfiltration Over C2 Channel
            })

    # Heuristic 2: High number of unique destinations for a single source IP
    if {"src_ip", "dst_ip"}.issubset(df.columns):
        group = df.groupby("src_ip")["dst_ip"].nunique()
        if not group.empty:
            cutoff = group.quantile(0.99)
            noisy_sources = group[group > cutoff].index.tolist()
            for src in noisy_sources:
                rows = df.index[df["src_ip"] == src].tolist()
                for idx in rows[:5]:  # limit spam
                    anomalies.append({
                        "id": f"ANOM-NET-FANOUT-{idx}",
                        "score": 0.90,
                        "reason": (
                            f"Source IP {src} is communicating with an unusually "
                            f"high number of destinations."
                        ),
                        "row_index": idx,
                        "log_type": "network",
                        "tags": ["anomaly", "recon_suspected"],
                        "mitre": ["T1046"],  # Network Service Scanning
                    })

    return anomalies


def _detect_auth_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []

    # Try to be flexible about column names
    user_col = None
    for candidate in ("username", "user", "account"):
        if candidate in df.columns:
            user_col = candidate
            break

    status_col = None
    for candidate in ("status", "result", "event_type", "login"):
        if candidate in df.columns:
            status_col = candidate
            break

    # Heuristic 1: Burst of failed logins for a username
    if user_col and status_col:
        failed = df[df[status_col].astype(str).str.upper().str.contains("FAIL")]
        if not failed.empty:
            fail_counts = failed[user_col].astype(str).value_counts()
            if not fail_counts.empty:
                cutoff = fail_counts.quantile(0.99)
                noisy_users = fail_counts[fail_counts > cutoff].index.tolist()
                for user in noisy_users:
                    rows = df.index[df[user_col].astype(str) == str(user)].tolist()
                    for idx in rows[:5]:
                        anomalies.append({
                            "id": f"ANOM-AUTH-FAIL-BURST-{idx}",
                            "score": 0.93,
                            "reason": (
                                f"Unusually high number of failed logins "
                                f"for user '{user}'."
                            ),
                            "row_index": idx,
                            "log_type": "auth",
                            "tags": ["anomaly", "credential_attack_suspected"],
                            "mitre": ["T1110"],  # Brute Force / Credential Stuffing
                        })

    # Heuristic 2: Rare geo-location for a user (if such fields exist)
    if user_col and "geo" in df.columns:
        grouped = df.groupby(user_col)
        for user, g in grouped:
            if len(g) < 5:
                continue
            geo_counts = g["geo"].value_counts()
            rare_geos = geo_counts[geo_counts == 1].index.tolist()
            for geo in rare_geos:
                rare_rows = g.index[g["geo"] == geo].tolist()
                for idx in rare_rows:
                    anomalies.append({
                        "id": f"ANOM-AUTH-RARE-GEO-{idx}",
                        "score": 0.90,
                        "reason": f"Rare geo-location '{geo}' seen for user '{user}'.",
                        "row_index": idx,
                        "log_type": "auth",
                        "tags": ["anomaly", "geo_anomaly"],
                        "mitre": ["T1078"],  # Valid Accounts / unusual use
                    })

    return anomalies


def _detect_endpoint_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []

    # Heuristic 1: Unusual process names
    proc_col = None
    for candidate in ("process_name", "image", "exe", "process"):
        if candidate in df.columns:
            proc_col = candidate
            break

    if proc_col:
        counts = df[proc_col].astype(str).value_counts()
        rare_names = counts[counts <= 2].index.tolist()
        for pname in rare_names:
            idx_list = df.index[df[proc_col].astype(str) == str(pname)].tolist()
            for idx in idx_list:
                anomalies.append({
                    "id": f"ANOM-END-RARE-PROC-{idx}",
                    "score": 0.88,
                    "reason": (
                        f"Process '{pname}' is rarely observed across endpoints "
                        f"in this dataset."
                    ),
                    "row_index": idx,
                    "log_type": "endpoint",
                    "tags": ["anomaly", "rare_process"],
                    "mitre": ["T1204"],  # User Execution
                })

    # Heuristic 2: High memory or CPU usage spikes if such fields exist
    mem_series = _safe_numeric_series(df, "memory_mb")
    if mem_series is None:
        mem_series = _safe_numeric_series(df, "memory")

    if mem_series is not None:
        out_idx = _zscore_outliers(mem_series, threshold=3.5)
        for idx in out_idx:
            anomalies.append({
                "id": f"ANOM-END-MEM-SPIKE-{idx}",
                "score": 0.90,
                "reason": "Unusual memory usage spike for this process compared to peers.",
                "row_index": idx,
                "log_type": "endpoint",
                "tags": ["anomaly", "resource_spike"],
                "mitre": [],
            })

    return anomalies


def _detect_exfiltration_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []

    # Heuristic: Unusually large file transfer if file_size or similar exists
    size_series = (
        _safe_numeric_series(df, "file_size_mb")
        or _safe_numeric_series(df, "file_size")
        or _safe_numeric_series(df, "bytes_out")
        or _safe_numeric_series(df, "bytes_sent")
    )
    if size_series is not None:
        out_idx = _percentile_outliers(size_series, low=0.0, high=0.995)
        for idx in out_idx:
            anomalies.append({
                "id": f"ANOM-EXF-LARGE-FILE-{idx}",
                "score": 0.94,
                "reason": "Unusually large data transfer compared to other entries.",
                "row_index": idx,
                "log_type": "exfiltration",
                "tags": ["anomaly", "exfiltration_suspected"],
                "mitre": ["T1567"],
            })

    return anomalies


# ─────────────────────────────────────────────────────────────
# Generic / Any-CSV Anomaly Heuristics
# ─────────────────────────────────────────────────────────────

def _detect_generic_numeric_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Schema-agnostic detector:
    - Looks at up to 10 numeric columns.
    - Flags high and low outliers.
    - If no strong outliers, still highlights the most extreme values.
    """
    anomalies: List[Dict[str, Any]] = []

    max_columns = 10
    numeric_cols: List[str] = []

    for col in df.columns:
        if len(numeric_cols) >= max_columns:
            break
        s = _safe_numeric_series(df, col)
        if s is not None:
            numeric_cols.append(col)

    for col in numeric_cols:
        s = _safe_numeric_series(df, col)
        if s is None:
            continue

        # 1) percentile-based outliers (more sensitive than before)
        idxs = _percentile_outliers(s, low=0.02, high=0.98)

        # 2) z-score backup with a looser threshold
        if len(idxs) == 0:
            idxs = _zscore_outliers(s, threshold=2.5)

        idxs = _ensure_unique(idxs)

        # 3) If still nothing but column has data, pick the single min and max
        if len(idxs) == 0 and s.notna().sum() > 0:
            min_idx = int(s.idxmin())
            max_idx = int(s.idxmax())
            idxs = _ensure_unique([min_idx, max_idx])

        for idx in idxs[:10]:
            value = s.loc[idx]
            anomalies.append({
                "id": f"ANOM-GENERIC-NUM-{col}-{idx}",
                "score": 0.80,
                "reason": (
                    f"Value {value!r} in numeric field '{col}' is unusually high or "
                    f"low compared to the rest of this file."
                ),
                "row_index": idx,
                "log_type": "unknown",
                "tags": ["anomaly", "generic_outlier"],
                "mitre": [],
            })

    return anomalies


def _detect_generic_rare_categories(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Generic categorical anomaly detector:
    - For text / categorical columns with enough rows,
      flags values that appear only once.
    """
    anomalies: List[Dict[str, Any]] = []
    max_columns = 10
    cat_cols: List[str] = []

    # choose likely categorical columns (non-numeric)
    for col in df.columns:
        if len(cat_cols) >= max_columns:
            break
        if _safe_numeric_series(df, col) is None:
            cat_cols.append(col)

    for col in cat_cols:
        series = df[col].astype(str)
        if series.nunique() < 3:
            continue  # too few categories to be interesting
        if len(series) < 20:
            continue  # tiny datasets are noisy

        counts = series.value_counts()
        rare_values = counts[counts == 1].index.tolist()
        if not rare_values:
            continue

        for val in rare_values[:20]:
            idxs = df.index[series == val].tolist()
            for idx in idxs:
                anomalies.append({
                    "id": f"ANOM-GENERIC-RARECAT-{col}-{idx}",
                    "score": 0.78,
                    "reason": (
                        f"Value '{val}' in field '{col}' is seen only once in this "
                        f"dataset, which is unusual for this column."
                    ),
                    "row_index": idx,
                    "log_type": "unknown",
                    "tags": ["anomaly", "rare_category"],
                    "mitre": [],
                })

    return anomalies


# ─────────────────────────────────────────────────────────────
# Log-type inference for auto mode
# ─────────────────────────────────────────────────────────────

def _infer_log_types_from_columns(df: pd.DataFrame) -> List[str]:
    """
    Look at column names and guess which log domain(s) this file
    most likely belongs to. This is intentionally simple & heuristic.
    """
    cols = {c.lower() for c in df.columns}
    candidates: List[str] = []

    # auth-like
    if any(c in cols for c in ("username", "user", "account")) and \
       any(c in cols for c in ("status", "result", "event_type", "login")):
        candidates.append("auth")

    # network-like
    if any("ip" in c for c in cols) or any(c in cols for c in ("src_ip", "dst_ip", "port")):
        candidates.append("network")

    # endpoint-like
    if any(c in cols for c in ("process_name", "image", "exe", "pid", "commandline")):
        candidates.append("endpoint")

    # exfiltration-like
    if any(c in cols for c in ("file_size", "file_size_mb", "bytes_out", "upload")):
        candidates.append("exfiltration")

    # If nothing matched, just say "unknown"
    if not candidates:
        candidates.append("unknown")

    # De-duplicate while preserving order
    seen = set()
    final = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            final.append(c)
    return final


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def run_anomaly_detection(df: pd.DataFrame, log_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Main entry point for Umbra's anomaly engine.

    df:       Parsed log data (from uploaded CSV).
    log_type: "auth" | "network" | "endpoint" | "exfiltration" | "auto" | None

    Returns a list of anomaly dictionaries ready to feed into
    alert_builder.build_anomaly_alerts(...).
    """
    if df is None or df.empty:
        return []

    log_type_norm = (log_type or "").lower()
    anomalies: List[Dict[str, Any]] = []

    # Explicit / single-domain mode
    if log_type_norm in {"network", "auth", "endpoint", "exfiltration"}:
        if log_type_norm == "network":
            anomalies.extend(_detect_network_anomalies(df))
        elif log_type_norm == "auth":
            anomalies.extend(_detect_auth_anomalies(df))
        elif log_type_norm == "endpoint":
            anomalies.extend(_detect_endpoint_anomalies(df))
        elif log_type_norm == "exfiltration":
            anomalies.extend(_detect_exfiltration_anomalies(df))
    else:
        # AUTO / UNKNOWN MODE:
        inferred_types = _infer_log_types_from_columns(df)

        if "network" in inferred_types:
            anomalies.extend(_detect_network_anomalies(df))
        if "auth" in inferred_types:
            anomalies.extend(_detect_auth_anomalies(df))
        if "endpoint" in inferred_types:
            anomalies.extend(_detect_endpoint_anomalies(df))
        if "exfiltration" in inferred_types:
            anomalies.extend(_detect_exfiltration_anomalies(df))
        # If "unknown", we just rely on the generic detectors below.

    # Generic detectors always run so Umbra says *something* on weird CSVs
    anomalies.extend(_detect_generic_numeric_anomalies(df))
    anomalies.extend(_detect_generic_rare_categories(df))

    # Optional: dedupe by (row_index, reason)
    seen_keys = set()
    deduped: List[Dict[str, Any]] = []
    for a in anomalies:
        key = (a.get("row_index"), a.get("reason"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(a)

    return deduped
