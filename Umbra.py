# =======================================================================
#   © 2025 TRIDENT-PRODUCTIONS STUDIO LLC — ALL RIGHTS RESERVED
# -----------------------------------------------------------------------
#   U M B R A   |   T R I D E N T   D I V I S I O N
#   BLACKSITE THREAT INTELLIGENCE OPERATIONS PLATFORM
#
#   CLASSIFICATION: LEVEL OMEGA
#
#   This software and its components are proprietary assets of
#   Trident-Productions Studio LLC. Unauthorized copying, distribution,
#   or reverse engineering is strictly prohibited under U.S. and
#   international intellectual property law.
# =======================================================================

import io
import json
from pathlib import Path

import pandas as pd
import streamlit as st
from datetime import datetime  


def _json_default(obj):
    # Handle pandas + datetime objects cleanly
    if isinstance(obj, (datetime, pd.Timestamp)):
        return obj.isoformat()
    # Fallback: just cast to string so nothing breaks
    return str(obj)

# ─────────────────────────────────────────
# Session bootstrap
# ─────────────────────────────────────────

if "gate_passed" not in st.session_state:
    st.session_state["gate_passed"] = False

if "agent_name" not in st.session_state:
    st.session_state["agent_name"] = ""

if "umbra_ctx" not in st.session_state:
    st.session_state["umbra_ctx"] = None

# cache for MITRE ATT&CK → D3FEND mappings (creator-only feature)
if "d3fend_cache" not in st.session_state:
    st.session_state["d3fend_cache"] = {}

from engine.correlation_engine import correlate_alerts
from engine.detection_engine import run_detection
from engine.anomaly_engine import run_anomaly_detection
from engine.alert_builder import (
    build_rule_alerts,
    build_anomaly_alerts,
)
from engine.framework_mapper import map_alert_to_frameworks  # noqa: F401
from engine.mitre_mapper import infer_mitre_from_alert       # noqa: F401
from engine.persona_middleware import (
    get_umbra_context,
    get_welcome_line,
    attach_persona_to_alert,
)
from engine.schema_mapper import (
    infer_log_families_from_columns,
    normalize_df_for_family,
)

# Umbra's high-level log families
SUPPORTED_LOG_TYPES = [
    "auth",
    "network",
    "endpoint",
    "exfiltration",
    "email",
    "cloud",
    "threat_intel",
    "infostealer"
]

# ─────────────────────────────────────────
# Umbra Framework Options (for sidebar)
# ─────────────────────────────────────────

FRAMEWORK_OPTIONS = {
    "nist_ir": "NIST Incident Response (SP 800-61)",
    "mitre_attck": "MITRE ATT&CK",
    "mitre_d3fend": "MITRE D3FEND",
    "nist_csf": "NIST Cybersecurity Framework (CSF)",
    "cis_controls": "CIS Controls v8",
}

FUTURE_FRAMEWORKS = [
    "Cyber Kill Chain (future)",
    "ISO 27035 (future)",
    "ISO 27001/27002 (future)",
    "NIST 800-53 (future)",
    "NIST 800-30 (future)",
]

# ─────────────────────────────────────────
# Playbook pack loader (MITRE ATT&CK)
# ─────────────────────────────────────────

PLAYBOOKS_PATH = (
    Path(__file__).resolve().parent / "playbooks" / "mitre_playbooks.json"
)

try:
    raw_pb = json.loads(PLAYBOOKS_PATH.read_text(encoding="utf-8"))
    if isinstance(raw_pb, list) and raw_pb:
        MITRE_PLAYBOOKS = raw_pb[0].get("techniques", {})
    elif isinstance(raw_pb, dict):
        MITRE_PLAYBOOKS = raw_pb.get("techniques", {})
    else:
        MITRE_PLAYBOOKS = {}
except Exception:
    MITRE_PLAYBOOKS = {}


def render_playbook_block(tech_id: str, container, alert, sev: str, rule_id: str):
    """
    Render a single MITRE ATT&CK technique playbook block into `container`.
    Expects MITRE_PLAYBOOKS[tech_id] structure like your pack screenshot.
    """
    pb = MITRE_PLAYBOOKS.get(tech_id)
    if not pb:
        container.warning(
            f"No Umbra playbook found for technique `{tech_id}` in MITRE pack."
        )
        return

    title = pb.get("TITLE", "Untitled Playbook")
    classification = pb.get("CLASSIFICATION", "UNCLASSIFIED")
    sev_default = pb.get("SEVERITY_DEFAULT", "N/A")
    conf_default = pb.get("CONFIDENCE_DEFAULT", "N/A")
    sections = pb.get("SECTIONS", {})

    container.markdown("**Umbra Incident Response Playbook**")
    container.markdown(
        f"**Technique:** `{tech_id}`  &nbsp;&nbsp; "
        f"**Title:** {title}"
    )
    container.markdown(
        f"**Classification:** {classification}  &nbsp;&nbsp; "
        f"**Default Severity:** {sev_default}  &nbsp;&nbsp; "
        f"**Default Confidence:** {conf_default}"
    )
    container.markdown("---")

    # Section bullets (IDENTIFICATION, CONTAINMENT, COUNTERMEASURES, FORENSICS, etc.)
    for section_name, bullets in sections.items():
        container.markdown(f"**{section_name.title()}**")
        for line in bullets:
            container.markdown(f"- {line}")
        container.markdown("")

    # Creator-only: export full alert + playbook JSON
    if alert is not None:
        export_payload = {
            "alert_title": alert.get(
                "title", alert.get("short_message", "Untitled Alert")
            ),
            "rule_id": rule_id,
            "severity": sev,
            "technique": tech_id,
            "playbook": pb,
            "event": alert.get("event", {}),
        }
        export_json = json.dumps(
            export_payload,
            indent=2,
            default=_json_default,
)


        # make the widget key unique per alert instance
        uniq_suffix = (
            str(alert.get("id"))
            or str(alert.get("rule_id"))
            or str(id(alert))
        )

        container.download_button(
            "⬇️ Export Alert Playbook (JSON)",
            data=export_json,
            file_name=f"umbra_playbook_{tech_id}_{rule_id}.json",
            mime="application/json",
            key=f"export_playbook_{tech_id}_{rule_id}_{uniq_suffix}",
        )

# ─────────────────────────────────────────
# Anomaly playbook pack loader (Umbra-native)
# ─────────────────────────────────────────

ANOMALY_PLAYBOOKS_PATH = (
    Path(__file__).resolve().parent / "playbooks" / "mitre_anomaly_playbook.json"
)

try:
    raw_anom = json.loads(ANOMALY_PLAYBOOKS_PATH.read_text(encoding="utf-8"))
    if isinstance(raw_anom, list) and raw_anom:
        UMBRA_ANOMALY_PLAYBOOKS = raw_anom[0].get("anomalies", {})
    elif isinstance(raw_anom, dict):
        UMBRA_ANOMALY_PLAYBOOKS = raw_anom.get("anomalies", {})
    else:
        UMBRA_ANOMALY_PLAYBOOKS = {}
except Exception:
    UMBRA_ANOMALY_PLAYBOOKS = {}


# ─────────────────────────────────────────
# MITRE ATT&CK → MITRE D3FEND helper
# ─────────────────────────────────────────

def map_attack_to_d3fend(mitre_obj):
    """
    Lightweight ATT&CK → D3FEND mapper.

    `mitre_obj` can be:
      - dict with "techniques": [...]
      - list of technique IDs
      - anything else → returns empty list

    Returns a list of rows:
      {
        "technique": "Txxxx",
        "d3fend_controls": [...],
        "summary": "human guidance ..."
      }
    """
    # Normalize into a list of technique IDs
    if isinstance(mitre_obj, dict):
        techs = [str(t) for t in mitre_obj.get("techniques", [])]
    elif isinstance(mitre_obj, list):
        techs = [str(t) for t in mitre_obj]
    else:
        techs = []

    # Tiny starter map – extend whenever you want
    static_map = {
        "T1098": {
            "controls": [
                "Account Monitoring",
                "Strong Authentication",
                "Delegated Credential Management",
            ],
            "summary": (
                "Harden identity systems: monitor new key creation, "
                "enforce MFA on privileged accounts, and limit standing access."
            ),
        },
        "T1059": {
            "controls": [
                "Script Execution Restrictions",
                "Application Control",
                "Command-line Auditing",
            ],
            "summary": (
                "Limit and monitor script interpreters, enforce allow-listing, "
                "and log command-line arguments for rapid detection."
            ),
        },
        "T1003": {
            "controls": [
                "Memory Protection",
                "Credential Vaulting",
                "Endpoint Detection & Response",
            ],
            "summary": (
                "Protect credential material in memory, use secure vaults, "
                "and watch for suspicious access to LSASS and related processes."
            ),
        },
    }

    rows = []
    for tid in techs:
        info = static_map.get(
            tid,
            {
                "controls": ["Hardening", "Monitoring", "Containment"],
                "summary": (
                    f"Implement hardening, continuous monitoring, and containment "
                    f"controls aligned to ATT&CK technique {tid}."
                ),
            },
        )
        rows.append(
            {
                "technique": tid,
                "d3fend_controls": info["controls"],
                "summary": info["summary"],
            }
        )

    return rows


# ---------------------------
# Visual theme
# ---------------------------

def apply_umbra_theme(ctx):
    """
    Apply different visual accents depending on whether the operator is:
    - Creator (GOD MODE)
    - Agent (BLACKSITE ACCESS)
    """

    if ctx.is_creator:
        primary = "#F3C14C"          # deep tactical gold
        accent = "#C0A05B"           # soft warm highlight (lighter gold)
        badge_bg = "rgba(182, 144, 56, 0.15)"   # translucent gold background
        border_glow = "0 0 18px rgba(182, 144, 56, 0.35)"  # gold glow
    else:
        primary = "#4aa3ff"      # steel blue
        accent = "#ffb347"       # muted amber
        badge_bg = "rgba(74, 163, 255, 0.12)"
        border_glow = "0 0 12px rgba(74, 163, 255, 0.25)"

    st.markdown(
        f"""
    <style>
    .stApp {{
        background-color: #050608;
    }}

    .umbra-header-title {{
        font-size: 1.8rem;
        font-weight: 700;
        color: {primary};
        letter-spacing: 0.05em;
    }}

    .umbra-mode-pill {{
        display: inline-block;
        padding: 0.2rem 0.6rem;
        margin-top: 0.3rem;
        border-radius: 999px;
        border: 1px solid {primary};
        background: {badge_bg};
        color: {primary};
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
    }}

    .umbra-subcaption {{
        font-size: 0.85rem;
        color: #9ca3af;
        margin-top: 0.3rem;
    }}

    .umbra-alert {{
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.6rem;
        border: 1px solid #1f2933;
        background: #050b10;
    }}

    .umbra-alert.creator {{
        border-color: {primary};
        box-shadow: {border_glow};
    }}

    .umbra-alert.agent {{
        border-color: #1f2933;
        box-shadow: none;
    }}

    .umbra-alert-title {{
        font-weight: 600;
        color: #e5e7eb;
    }}

    .umbra-alert-meta {{
        font-size: 0.75rem;
        color: #9ca3af;
    }}

    .umbra-severity-badge {{
        display: inline-block;
        padding: 0.08rem 0.45rem;
        border-radius: 999px;
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }}

    .umbra-severity-critical {{
        background: rgba(239, 68, 68, 0.14);
        color: #fca5a5;
        border: 1px solid #ef4444;
    }}
    .umbra-severity-high {{
        background: rgba(245, 158, 11, 0.14);
        color: #fbbf24;
        border: 1px solid #f59e0b;
    }}
    .umbra-severity-medium {{
        background: rgba(59, 130, 246, 0.14);
        color: #93c5fd;
        border: 1px solid #3b82f6;
    }}
    .umbra-severity-low {{
        background: rgba(107, 114, 128, 0.18);
        color: #d1d5db;
        border: 1px solid #4b5563;
    }}

    .umbra-voice-line {{
        font-size: 0.8rem;
        font-style: italic;
        color: {accent};
        margin-top: 0.3rem;
        margin-bottom: 0.3rem;
    }}
    </style>
    """,
        unsafe_allow_html=True,
    )

# ---------------------------
# Streamlit app setup
# ---------------------------

st.set_page_config(
    page_title="Umbra | Trident Division",
    page_icon="🔱",
    layout="wide",
)

# ─────────────────────────────────────────
# GATE SCREEN (codename entry)
# ─────────────────────────────────────────

if not st.session_state["gate_passed"]:
    # Gate screen styling + Umbra card
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #0b1220 0, #020617 45%, #000 100%);
        }
        .umbra-gate-card {
            max-width: 520px;
            margin: 72px auto 24px auto;
            padding: 24px 36px;
            border-radius: 18px;
            background: rgba(15, 23, 42, 0.98);
            box-shadow: 0 28px 80px rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.4);
            text-align: center;
        }
        .umbra-gate-title {
            font-size: 22px;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            color: #e5e7eb;
            margin-bottom: 6px;
        }
        .umbra-gate-sub {
            font-size: 12px;
            color: #9ca3af;
        }
        </style>

        <div class="umbra-gate-card">
          <div class="umbra-gate-title">UMBRA | TRIDENT DIVISION</div>
          <div class="umbra-gate-sub">
            Blacksite systems online. Identification required to proceed.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Centered narrow input area using columns
    left, center, right = st.columns([2, 3, 2])  # tweak ratios to change width

    with center:
        codename = st.text_input(
            "Codename",
            placeholder="Enter codename",
            key="codename",
        )

        access = st.button("Access Umbra", use_container_width=True)

    if access and codename.strip():
        st.session_state["agent_name"] = codename.strip()
        st.session_state["gate_passed"] = True
        st.rerun()

    # Stop here so main UI doesn't render until gate is passed
    st.stop()

# ─────────────────────────────────────────
# Main app (after access granted)
# ─────────────────────────────────────────

agent_name = st.session_state.get("agent_name") or "Trident"
ctx = st.session_state.get("umbra_ctx") or get_umbra_context(agent_name)
# make sure persona knows the live codename
try:
    ctx.user_name = agent_name
except Exception:
    pass
st.session_state["umbra_ctx"] = ctx

apply_umbra_theme(ctx)

# Sidebar – read-only identity + future views
st.sidebar.markdown("### Operator Identification")
st.sidebar.markdown(f"**Codename:** {ctx.user_name}")
st.sidebar.markdown(f"**Clearance:** {ctx.clearance_label}")

st.sidebar.markdown("-----")
st.sidebar.markdown("**Future / Premium Views**")
for fw in FUTURE_FRAMEWORKS:
    st.sidebar.markdown(f"- {fw}")

# Header
st.markdown(
    "<div class='umbra-header-title'>Umbra | Trident Division</div>",
    unsafe_allow_html=True,
)
st.markdown(
    f"<div class='umbra-mode-pill'>{ctx.clearance_label}</div>",
    unsafe_allow_html=True,
)
st.markdown(
    f"<div class='umbra-subcaption'>Welcome to Umbra, Agent {ctx.user_name}. "
    f"Upload a signal from the Blacksite Data Vault to begin analysis.</div>",
    unsafe_allow_html=True,
)

st.markdown("---")

# ---- Main controls (mode + framework picker) ----
mode_col, fw_col = st.columns([2, 2])

with mode_col:
    log_mode = st.selectbox(
        "Select analysis mode",
        options=["auto"] + SUPPORTED_LOG_TYPES,
        index=0,
        format_func=lambda v: (
            "Auto-detect from Blacksite Data Vault (mixed logs)" if v == "auto"
            else f"{v} logs only"
        ),
    )

with fw_col:
    fw_options = list(FRAMEWORK_OPTIONS.keys()) + ["__ALL__"]
    fw_selection = st.multiselect(
        "Choose framework view",
        options=fw_options,
        # Default to MITRE ATT&CK instead of All frameworks
        default=["mitre_attck"],
        format_func=lambda k: (
            "All frameworks" if k == "__ALL__" else FRAMEWORK_OPTIONS[k]
        ),
        help="Select one or more frameworks. If left empty, Umbra falls back to MITRE ATT&CK.",
    )

# ─────────────────────────────────────────
# Framework Selection Logic
# ─────────────────────────────────────────
if not fw_selection:
    # If nothing is picked, fall back to MITRE ATT&CK
    selected_framework_keys = ["mitre_attck"]

elif "__ALL__" in fw_selection:
    # If All frameworks is selected, use everything
    selected_framework_keys = list(FRAMEWORK_OPTIONS.keys())

else:
    # Use only selected frameworks (excluding the __ALL__ marker)
    selected_framework_keys = [k for k in fw_selection if k != "__ALL__"]

uploaded_file = st.file_uploader(
    "Upload log file (CSV)",
    type=["csv"],
    help="Export your logs as CSV and drop them here.",
)

MAX_SIZE_AGENT_MB = 200  # standard limit
MAX_SIZE_CREATOR_MB = 1000  # expanded limit

if uploaded_file is not None:
    file_size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)

    if not ctx.is_creator and file_size_mb > MAX_SIZE_AGENT_MB:
        st.error(f"File exceeds {MAX_SIZE_AGENT_MB}MB limit for standard operators.")
        st.stop()

    if ctx.is_creator and file_size_mb > MAX_SIZE_CREATOR_MB:
        st.error(f"File exceeds Creator mode limit of {MAX_SIZE_CREATOR_MB}MB.")
        st.stop()

# Read the CSV ONCE per upload and cache it in session_state
if uploaded_file is not None:
    current_name = uploaded_file.name
    previous_name = st.session_state.get("uploaded_file_name")

    # If a new file is uploaded (or first time), re-parse
    if previous_name != current_name:
        try:
            # First pass: standard CSV
            df = pd.read_csv(uploaded_file)

            # Special case: Zeek-style '|' separated logs that came in as a single column
            if df.shape[1] == 1 and "|" in df.columns[0]:
                raw_bytes = uploaded_file.getvalue()
                try:
                    df = pd.read_csv(io.BytesIO(raw_bytes), sep="|")
                except Exception:
                    # If re-parse fails, just stick with original df
                    pass

            st.session_state["uploaded_df"] = df
            st.session_state["uploaded_file_name"] = current_name
        except Exception as e:
            st.error(f"Error processing file: {e}")
            st.stop()
else:
    # If the user clears the uploader, clear cached DF + name
    if "uploaded_df" in st.session_state:
        del st.session_state["uploaded_df"]
    if "uploaded_file_name" in st.session_state:
        del st.session_state["uploaded_file_name"]

analyze_clicked = st.button("Analyze with Umbra")

# ─────────────────────────────────────────
# Analysis flow
# ─────────────────────────────────────────

if analyze_clicked:
    try:
        df = st.session_state.get("uploaded_df")
        if df is None or df.empty:
            st.error("Upload a non-empty CSV first.")
            st.session_state["umbra_alerts"] = []
            st.stop()

        # rules live in ../rules
        rules_dir = Path(__file__).resolve().parent / "rules"

        all_rule_alerts: list[dict] = []
        all_anomaly_alerts: list[dict] = []

        # ------------ AUTO MODE (no family selected) ------------
        if log_mode == "auto":
            # Case 1: explicit log_type column in the CSV (your Umbra test logs)
            if "log_type" in df.columns:
                df["__umbra_log_type_norm"] = (
                    df["log_type"].astype(str).str.lower()
                )
                active_types = [
                    t for t in df["__umbra_log_type_norm"].unique()
                    if t in SUPPORTED_LOG_TYPES
                ]

                if not active_types:
                    # Fallback: run generic anomaly only
                    try:
                        anomaly_results = run_anomaly_detection(df, log_type=None)
                        all_anomaly_alerts.extend(
                            build_anomaly_alerts(anomaly_results, df, "unknown")
                        )
                    except Exception:
                        pass
                else:
                    for lt in active_types:
                        sub_df = df[df["__umbra_log_type_norm"] == lt]
                        if sub_df.empty:
                            continue

                        # Normalize dialect → Umbra schema for this family
                        norm_df = normalize_df_for_family(sub_df, lt)

                        # 1) rule-based
                        rule_matches = run_detection(norm_df, log_type=lt, rules_dir=rules_dir)
                        all_rule_alerts.extend(
                            build_rule_alerts(rule_matches, norm_df, lt)
                        )

                        # 2) anomaly-based
                        try:
                            anomaly_results = run_anomaly_detection(norm_df, log_type=lt)
                            all_anomaly_alerts.extend(
                                build_anomaly_alerts(anomaly_results, norm_df, lt)
                            )
                        except Exception:
                            continue

            # Case 2: NO log_type column – arbitrary CSV (Zeek, Kaggle, HIBP, etc.)
            else:
                inferred_families = infer_log_families_from_columns(df)
                # Keep only families Umbra knows, plus "unknown" if nothing useful
                families = [
                    f for f in inferred_families if f in SUPPORTED_LOG_TYPES
                ] or ["unknown"]

                for fam in families:
                    if fam == "unknown":
                        # No strong guess – generic anomaly only
                        try:
                            anomaly_results = run_anomaly_detection(df, log_type=None)
                            all_anomaly_alerts.extend(
                                build_anomaly_alerts(anomaly_results, df, "unknown")
                            )
                        except Exception:
                            continue
                        continue

                    # Normalize according to detected family
                    norm_df = normalize_df_for_family(df, fam)

                    # Rule-based (only works where rules exist – currently auth/network/endpoint/exfil)
                    try:
                        rule_matches = run_detection(norm_df, log_type=fam, rules_dir=rules_dir)
                        all_rule_alerts.extend(
                            build_rule_alerts(rule_matches, norm_df, fam)
                        )
                    except Exception:
                        # Missing rule pack? Just skip rules.
                        pass

                    # Anomaly-based
                    try:
                        anomaly_results = run_anomaly_detection(norm_df, log_type=fam)
                        all_anomaly_alerts.extend(
                            build_anomaly_alerts(anomaly_results, norm_df, fam)
                        )
                    except Exception:
                        continue

        # ------------ SINGLE-FAMILY MODE (dropdown) ------------
        else:
            lt = log_mode  # auth / network / endpoint / exfiltration / email / cloud / threat_intel

            # Normalize entire file for the selected family
            norm_df = normalize_df_for_family(df, lt)

            # Rules (if any exist for this family)
            try:
                rule_matches = run_detection(norm_df, log_type=lt, rules_dir=rules_dir)
                all_rule_alerts = build_rule_alerts(rule_matches, norm_df, lt)
            except Exception:
                all_rule_alerts = []

            # Anomalies
            try:
                anomaly_results = run_anomaly_detection(norm_df, log_type=lt)
                all_anomaly_alerts = build_anomaly_alerts(anomaly_results, norm_df, lt)
            except Exception:
                all_anomaly_alerts = []

        alerts = all_rule_alerts + all_anomaly_alerts

        # Defensive: make sure frameworks / mitre keys exist
        for a in alerts:
            a.setdefault("frameworks", {})
            if "mitre" not in a:
                a["mitre"] = []

        # Persona overlay
        persona_alerts = [attach_persona_to_alert(a, ctx) for a in alerts]

        # Cross-log correlation / kill-chain brain
        corr_alerts = correlate_alerts(persona_alerts)
        persona_corr_alerts = [attach_persona_to_alert(a, ctx) for a in corr_alerts]

        all_with_correlation = persona_alerts + persona_corr_alerts

        st.session_state["umbra_alerts"] = all_with_correlation

        # Status line so you know how much was detected
        st.caption(
            f"🧬 Blacksite Data Vault scan complete: "
            f"{len(all_rule_alerts)} rule alerts, "
            f"{len(all_anomaly_alerts)} anomaly alerts."
        )

    except Exception as e:
        st.error(f"Error processing file: {e}")
        st.session_state["umbra_alerts"] = []

# ---------------------------
# Render alerts (if any)
# ---------------------------

alerts = st.session_state.get("umbra_alerts", [])

if not alerts:
    st.info("No alerts detected yet. Upload a CSV and click **Analyze with Umbra**.")
else:
    # ---- Detection summary ----
    st.subheader("Detection Summary")

    severity_counts: dict[str, int] = {}
    for a in alerts:
        if not isinstance(a, dict):
            continue
        sev = (a.get("severity") or "medium").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    col1, col2, col3, col4 = st.columns(4)
    for sev, col in zip(
        ["critical", "high", "medium", "low"],
        [col1, col2, col3, col4],
    ):
        col.metric(label=sev.capitalize(), value=severity_counts.get(sev, 0))

    # tight divider + single Alerts header (no extra copies)
    st.markdown(
        "<hr style='margin-top:24px;margin-bottom:8px;'>",
        unsafe_allow_html=True,
    )
    st.markdown("### Alerts", unsafe_allow_html=True)

    # ---- Order + render alerts ----
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    alerts_sorted = sorted(
        [a for a in alerts if isinstance(a, dict)],
        key=lambda a: (
            sev_order.get((a.get("severity") or "medium").lower(), 99),
            str(a.get("rule_id") or a.get("id") or ""),
        ),
    )

    for idx, alert in enumerate(alerts_sorted):
        sev = (alert.get("severity") or "medium").lower()
        risk = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
        }.get(sev, "MEDIUM")

        rule_id = alert.get("rule_id", alert.get("id", "N/A"))

        severity_class = f"umbra-severity-{sev}"
        alert_mode_class = "creator" if ctx.is_creator else "agent"

        title_html = f"""
        <div class="umbra-alert {alert_mode_class}">
          <div class="umbra-alert-title">
            <span class="umbra-severity-badge {severity_class}">{sev.upper()}</span>
            &nbsp; {alert.get('title', alert.get('short_message', 'Untitled Alert'))}
          </div>
          <div class="umbra-alert-meta">
            Risk: {risk} &nbsp;|&nbsp; Rule: {rule_id}
          </div>
          <div class="umbra-voice-line">
            {alert.get('umbra_voice_line', '')}
          </div>
          <div style="font-size: 0.85rem; color: #d1d5db;">
            {alert.get('summary', alert.get('description', ''))}
          </div>
        </div>
        """
        st.markdown(title_html, unsafe_allow_html=True)

        with st.expander("View details"):
            st.write("**Description**")
            st.write(alert.get("description", ""))

            st.write("**Anomaly Signals**")
            for sig in alert.get("anomaly", {}).get("signals", []):
                st.markdown(f"- {sig}")

            # ── MITRE Techniques ─────────────────────
            st.write("**MITRE Techniques**")
            mitre = alert.get("mitre", {})

            if isinstance(mitre, dict) and mitre.get("techniques"):
                mitre_tech_list = [str(t) for t in mitre["techniques"]]
                st.code(", ".join(mitre_tech_list))
            elif isinstance(mitre, list):
                mitre_tech_list = [str(t) for t in mitre]
                st.code(", ".join(mitre_tech_list))
            else:
                mitre_tech_list = []
                st.write("None specified")

            # ── Framework Guidance + D3FEND mapping ──
            st.write("**Framework Guidance**")
            frameworks = alert.get("frameworks", {})
            any_fw_shown = False

            for fw_key in selected_framework_keys:
                if fw_key in frameworks:
                    any_fw_shown = True

                    # Special handling for MITRE ATT&CK
                    if fw_key == "mitre_attck":
                        # Header label
                        st.markdown(f"- **{FRAMEWORK_OPTIONS[fw_key]}**")

                        # One row: Export | Map | Playbook
                        btn_col_export, btn_col_map, btn_col_pb = st.columns(
                            [1, 1, 1]
                        )

                        # Precompute default D3FEND rows for this alert
                        d3_rows_default = (
                            map_attack_to_d3fend(mitre)
                            if mitre_tech_list
                            else []
                        )

                        # Creator-only per-alert export (left button)
                        if ctx.is_creator:
                            export_payload = {
                                "alert_title": alert.get(
                                    "title",
                                    alert.get("short_message", "Untitled Alert"),
                                ),
                                "severity": sev,
                                "rule_id": rule_id,
                                "mitre_techniques": mitre_tech_list,
                                "mitre_framework": frameworks[fw_key],
                                "d3fend": d3_rows_default,
                                "event": alert.get("event", {}),
                            }
                            export_json = json.dumps(export_payload, indent=2)
                            with btn_col_export:
                                st.download_button(
                                    "⬇️ Export Alert (JSON)",
                                    data=export_json,
                                    file_name=f"umbra_alert_{rule_id}.json",
                                    mime="application/json",
                                    key=f"export_alert_{idx}_{rule_id}",
                                )
                        else:
                            with btn_col_export:
                                st.empty()

                        # Creator-only D3FEND button (middle)
                        if ctx.is_creator and mitre_tech_list:
                            base_key = str(
                                rule_id or alert.get("id") or f"idx_{idx}"
                            )
                            alert_key = f"{base_key}__{'_'.join(mitre_tech_list)}"
                            ui_key = f"d3fend_btn_{idx}_{alert_key}"

                            with btn_col_map:
                                defend_btn = st.button(
                                    "Map to MITRE D3FEND",
                                    key=ui_key,
                                    help="Translate these ATT&CK techniques into defensive D3FEND controls.",
                                )
                        else:
                            with btn_col_map:
                                st.empty()
                            defend_btn = False
                            alert_key = None

                        # Playbook button (right)
                        # Choose first technique that has a playbook defined
                        playbook_tid = next(
                            (
                                t
                                for t in mitre_tech_list
                                if t in MITRE_PLAYBOOKS
                            ),
                            None,
                        )
                        if ctx.is_creator and playbook_tid:
                            with btn_col_pb:
                                pb_btn = st.button(
                                    "Generate Playbook",
                                    key=f"pb_btn_{idx}_{rule_id}_{playbook_tid}",
                                )
                        else:
                            with btn_col_pb:
                                pb_btn = False
                                if ctx.is_creator and mitre_tech_list:
                                    st.caption("No playbook in pack.")

                        # Existing ATT&CK JSON mapping
                        st.json(frameworks[fw_key])

                        # Creator-only: generate + persist D3FEND mapping, then render
                        if ctx.is_creator and mitre_tech_list and alert_key:
                            cache = st.session_state["d3fend_cache"]

                            if defend_btn:
                                cache[alert_key] = {
                                    "alert_title": alert.get(
                                        "title",
                                        alert.get(
                                            "short_message", "Untitled Alert"
                                        ),
                                    ),
                                    "severity": sev,
                                    "rule_id": rule_id,
                                    "mitre_techniques": mitre_tech_list,
                                    "d3fend": d3_rows_default,
                                }

                            cached = cache.get(alert_key)
                            if cached:
                                st.markdown(
                                    "**D3FEND Countermeasures (Table)**"
                                )
                                d3_table = [
                                    {
                                        "Technique": row["technique"],
                                        "Controls": ", ".join(
                                            row["d3fend_controls"]
                                        ),
                                    }
                                    for row in cached["d3fend"]
                                ]
                                st.table(pd.DataFrame(d3_table))

                                st.markdown("**D3FEND Narrative Guidance**")
                                for row in cached["d3fend"]:
                                    st.markdown(
                                        f"- **{row['technique']}**: {row['summary']}"
                                    )

                        # Playbook rendering beneath D3FEND (if clicked)
                        if ctx.is_creator and playbook_tid:
                            state_key = (
                                f"playbook_visible_{idx}_{rule_id}_{playbook_tid}"
                            )
                            if pb_btn:
                                st.session_state[state_key] = True

                            if st.session_state.get(state_key):
                                render_playbook_block(
                                    playbook_tid, st, alert, sev, rule_id
                                )

                    # All non-ATT&CK frameworks behave as before
                    else:
                        st.markdown(f"- **{FRAMEWORK_OPTIONS[fw_key]}**")
                        st.json(frameworks[fw_key])

            if not any_fw_shown:
                st.write("No framework mappings attached to this alert.")

            st.write("**Raw Record**")
            st.json(alert.get("event", {}))

        st.markdown("---")


def render_anomaly_playbook_block(anom_key: str, container, alert, sev: str, rule_id: str):
    """
    Render an Umbra anomaly playbook (no MITRE technique).
    Uses UMBRA_ANOMALY_PLAYBOOKS[anom_key].
    """
    pb = UMBRA_ANOMALY_PLAYBOOKS.get(anom_key)
    if not pb:
        container.warning(
            f"No Umbra anomaly playbook found for key `{anom_key}` in ANOMALY pack."
        )
        return

    title = pb.get("TITLE", "Unnamed Anomaly Pattern")
    risk_theme = pb.get("RISK_THEME", "ANOMALY")
    sev_default = pb.get("SEVERITY_DEFAULT", "N/A")
    conf_default = pb.get("CONFIDENCE_DEFAULT", "N/A")
    sections = pb.get("SECTIONS", {})
    examples = pb.get("SIGNAL_EXAMPLES", [])

    container.markdown("**Umbra Anomaly Response Playbook**")
    container.markdown(
        f"**Playbook Key:** `{anom_key}`  &nbsp;&nbsp; "
        f"**Title:** {title}"
    )
    container.markdown(
        f"**Risk Theme:** {risk_theme}  &nbsp;&nbsp; "
        f"**Default Severity:** {sev_default}  &nbsp;&nbsp; "
        f"**Default Confidence:** {conf_default}"
    )

    if examples:
        container.markdown("**Signal Examples**")
        for ex in examples:
            container.markdown(f"- {ex}")
        container.markdown("---")

    # Section bullets: ASSESSMENT / OPERATOR_DIRECTIVES / ESCALATION_CONDITIONS / etc.
    for section_name, bullets in sections.items():
        container.markdown(f"**{section_name.replace('_', ' ').title()}**")
        for line in bullets:
            container.markdown(f"- {line}")
        container.markdown("")

    # Optional: export full alert + anomaly playbook as JSON
    if alert is not None:
        export_payload = {
            "alert_title": alert.get(
                "title", alert.get("short_message", "Untitled Alert")
            ),
            "rule_id": rule_id,
            "severity": sev,
            "anomaly_playbook_key": anom_key,
            "playbook": pb,
            "event": alert.get("event", {}),
        }
        export_json = json.dumps(export_payload, indent=2)

        uniq_suffix = (
            str(alert.get("id"))
            or str(alert.get("rule_id"))
            or str(id(alert))
        )

        container.download_button(
            "⬇️ Export Anomaly Playbook (JSON)",
            data=export_json,
            file_name=f"umbra_anomaly_playbook_{anom_key}_{rule_id}.json",
            mime="application/json",
            key=f"export_anom_playbook_{anom_key}_{rule_id}_{uniq_suffix}",
        )
