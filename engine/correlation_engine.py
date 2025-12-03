# engine/correlation_engine.py
# -------------------------------------------------------------------
# Umbra cross-log correlation engine ("Kill Chain Brain")
# -------------------------------------------------------------------

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone, timedelta


Severity = str
Alert = Dict[str, Any]


# -----------------------------
# Helpers
# -----------------------------

def _parse_timestamp(event: Dict[str, Any]) -> Optional[datetime]:
    """
    Try to parse a timestamp out of the raw event object.
    Supports:
      - ISO strings: 2025-01-15T10:00:00Z, 2025-01-15 10:00:00
      - Epoch seconds or milliseconds (int/float)
      - Zeek-style "ts" float seconds
    Returns a timezone-aware UTC datetime or None.
    """
    if not isinstance(event, dict):
        return None

    ts_fields = ["timestamp", "@timestamp", "time", "ts", "event_time"]

    for f in ts_fields:
        if f not in event:
            continue
        val = event[f]

        # numeric epoch
        if isinstance(val, (int, float)):
            # Heuristic: ms vs s
            if val > 10_000_000_000:  # > ~year 2286 in seconds, so assume ms
                val = val / 1000.0
            try:
                return datetime.fromtimestamp(float(val), tz=timezone.utc)
            except Exception:
                continue

        # string datetime or epoch
        if isinstance(val, str):
            v = val.strip()
            # epoch in string form
            try:
                fval = float(v)
                if fval > 10_000_000_000:
                    fval = fval / 1000.0
                return datetime.fromtimestamp(fval, tz=timezone.utc)
            except Exception:
                pass

            # ISO-ish
            try:
                if v.endswith("Z"):
                    v = v[:-1] + "+00:00"
                return datetime.fromisoformat(v)
            except Exception:
                continue

    return None


def _extract_principal(event: Dict[str, Any]) -> str:
    """
    Try to derive a stable 'principal' for correlation:
      - user / username / account / principal
      - or src_ip / source_ip
      - or host / hostname
    Falls back to 'unknown' if nothing useful is found.
    """
    if not isinstance(event, dict):
        return "unknown"

    # user-like
    for f in ("user", "username", "account", "principal", "subject"):
        if f in event and event[f]:
            return f"user:{str(event[f])}"

    # IP-like
    for f in ("src_ip", "source_ip", "client_ip", "ip"):
        if f in event and event[f]:
            return f"ip:{str(event[f])}"

    # host-like
    for f in ("host", "hostname", "device", "endpoint"):
        if f in event and event[f]:
            return f"host:{str(event[f])}"

    return "unknown"


_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _sev_rank(sev: Severity) -> int:
    return _SEV_ORDER.get(str(sev).lower(), 1)


def _has_tag(alert: Alert, tag: str) -> bool:
    tags = alert.get("tags") or []
    return any(str(t).lower() == tag for t in tags)


def _has_tag_like(alert: Alert, substring: str) -> bool:
    tags = alert.get("tags") or []
    sub = substring.lower()
    return any(sub in str(t).lower() for t in tags)


def _collect_mitre(alerts: List[Alert]) -> List[str]:
    seen = set()
    out: List[str] = []
    for a in alerts:
        m = a.get("mitre") or []
        if isinstance(m, dict) and m.get("techniques"):
            m = m["techniques"]
        if not isinstance(m, (list, tuple)):
            continue
        for t in m:
            t_str = str(t)
            if t_str not in seen:
                seen.add(t_str)
                out.append(t_str)
    return out


# -----------------------------
# Core correlation
# -----------------------------

def _enrich_alerts(alerts: List[Alert]) -> List[Dict[str, Any]]:
    """Attach parsed timestamp + principal for correlation."""
    enriched: List[Dict[str, Any]] = []

    for a in alerts:
        event = a.get("event") or {}
        ts = _parse_timestamp(event)
        principal = _extract_principal(event)
        enriched.append(
            {
                "alert": a,
                "ts": ts,
                "principal": principal,
            }
        )

    # Keep alerts without timestamp at the end
    enriched.sort(
        key=lambda x: x["ts"] if isinstance(x["ts"], datetime) else datetime.max.replace(tzinfo=timezone.utc)
    )
    return enriched


def _group_by_principal(enriched: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_p: Dict[str, List[Dict[str, Any]]] = {}
    for e in enriched:
        by_p.setdefault(e["principal"], []).append(e)
    # sort each principal's alerts by ts
    for p in by_p:
        by_p[p].sort(
            key=lambda x: x["ts"] if isinstance(x["ts"], datetime) else datetime.max.replace(tzinfo=timezone.utc)
        )
    return by_p


def correlate_alerts(
    alerts: List[Alert],
    time_window_minutes: int = 45,
    max_alerts: int = 5000,
) -> List[Alert]:
    """
    Take raw Umbra alerts (from all log types) and emit *meta-alerts*
    that represent multi-stage kill chains.

    This is intentionally lightweight:
      - uses alert timestamps + principals (user/ip/host)
      - looks for chained patterns within a time window
      - returns new alerts with log_type="correlated"
    """
    if not alerts:
        return []

    # Avoid blowing up on huge runs
    if len(alerts) > max_alerts:
        alerts = alerts[:max_alerts]

    enriched = _enrich_alerts(alerts)
    by_principal = _group_by_principal(enriched)
    window = timedelta(minutes=time_window_minutes)

    correlated: List[Alert] = []

    # Pattern 1: Auth compromise -> Endpoint malware -> Exfiltration
    for principal, items in by_principal.items():
        if principal == "unknown":
            continue

        # split by type for convenience
        auth_events = [
            e for e in items
            if (e["alert"].get("log_type") == "auth") or _has_tag(e["alert"], "auth")
        ]
        endpoint_events = [
            e for e in items
            if (e["alert"].get("log_type") == "endpoint") or _has_tag(e["alert"], "endpoint")
        ]
        exfil_events = [
            e for e in items
            if (
                e["alert"].get("log_type") in {"exfiltration", "network", "cloud"}
                and (_has_tag_like(e["alert"], "exfil") or _has_tag_like(e["alert"], "egress"))
            )
        ]

        if not auth_events or not endpoint_events or not exfil_events:
            continue

        # pick "anchor" auth event and see if we can find matching endpoint/exfil nearby
        for a_e in auth_events:
            ts_a = a_e["ts"]
            if not isinstance(ts_a, datetime):
                continue
            # require reasonably high severity on the auth piece
            if _sev_rank(a_e["alert"].get("severity", "medium")) < _SEV_ORDER["high"]:
                continue

            # find closest endpoint + exfil events within window
            endpoint_match: Optional[Dict[str, Any]] = None
            exfil_match: Optional[Dict[str, Any]] = None

            for ep_e in endpoint_events:
                ts_ep = ep_e["ts"]
                if not isinstance(ts_ep, datetime):
                    continue
                if abs(ts_ep - ts_a) <= window:
                    endpoint_match = ep_e
                    break

            for ex_e in exfil_events:
                ts_ex = ex_e["ts"]
                if not isinstance(ts_ex, datetime):
                    continue
                if abs(ts_ex - ts_a) <= window:
                    exfil_match = ex_e
                    break

            if not endpoint_match or not exfil_match:
                continue

            a_alert = a_e["alert"]
            ep_alert = endpoint_match["alert"]
            ex_alert = exfil_match["alert"]

            base_ts = ts_a.isoformat()

            meta_id = f"CORR-KILLCHAIN-AUTH-ENDPOINT-EXFIL-{principal}-{base_ts}"
            meta_alert: Alert = {
                "id": meta_id,
                "rule_id": "CORR_KILLCHAIN_01",
                "title": "[CRITICAL] Kill chain: Account compromise → Endpoint malware → Data exfiltration",
                "short_message": "Umbra linked auth, endpoint, and exfiltration activity into a single multi-stage attack.",
                "log_type": "correlated",
                "severity": "critical",
                "summary": (
                    f"Principal {principal} shows a chained pattern: "
                    f"authentication compromise, endpoint malware activity, and data exfiltration "
                    f"within ~{time_window_minutes} minutes."
                ),
                "description": (
                    "Umbra observed high-severity authentication anomalies followed by suspicious "
                    "endpoint activity and high-risk egress/exfiltration from the same principal. "
                    "Taken together, this strongly resembles a successful compromise with data theft.\n\n"
                    "This is a *correlated* alert synthesized from multiple underlying detections, "
                    "not a single raw rule match."
                ),
                "tags": [
                    "correlated",
                    "killchain",
                    "multi-stage",
                    "auth",
                    "endpoint",
                    "exfiltration",
                ],
                "mitre": _collect_mitre([a_alert, ep_alert, ex_alert]),
                "frameworks": {},
                "event": {
                    "correlated_principal": principal,
                    "time_window_minutes": time_window_minutes,
                    "auth_alert_id": a_alert.get("id") or a_alert.get("rule_id"),
                    "endpoint_alert_id": ep_alert.get("id") or ep_alert.get("rule_id"),
                    "exfil_alert_id": ex_alert.get("id") or ex_alert.get("rule_id"),
                    "auth_event": a_alert.get("event", {}),
                    "endpoint_event": ep_alert.get("event", {}),
                    "exfil_event": ex_alert.get("event", {}),
                },
                "anomaly": {
                    "signals": [
                        "Cross-log inference: auth + endpoint + exfiltration chained for same principal.",
                        "Behavior consistent with successful compromise and data theft.",
                    ]
                },
            }

            correlated.append(meta_alert)
            # Prevent spamming multiple meta-alerts for same principal
            break

    # Pattern 2: Cloud unusual login + key creation (persistence)
    for principal, items in by_principal.items():
        cloud_events = [
            e for e in items
            if e["alert"].get("log_type") == "cloud"
        ]
        if not cloud_events:
            continue

        login_events = [
            e for e in cloud_events
            if _has_tag_like(e["alert"], "geo_anomaly")
        ]
        key_events = [
            e for e in cloud_events
            if _has_tag_like(e["alert"], "iam") or "access key" in str(e["alert"].get("name", "")).lower()
        ]

        if not login_events or not key_events:
            continue

        for lg in login_events:
            ts_lg = lg["ts"]
            if not isinstance(ts_lg, datetime):
                continue

            matching_key = None
            for ke in key_events:
                ts_ke = ke["ts"]
                if not isinstance(ts_ke, datetime):
                    continue
                if abs(ts_ke - ts_lg) <= window:
                    matching_key = ke
                    break

            if not matching_key:
                continue

            lg_a = lg["alert"]
            ke_a = matching_key["alert"]
            base_ts = ts_lg.isoformat()

            meta_id = f"CORR-CLOUD-PERSISTENCE-{principal}-{base_ts}"
            meta_alert: Alert = {
                "id": meta_id,
                "rule_id": "CORR_CLOUD_CHAIN_01",
                "title": "[HIGH] Suspicious cloud login followed by new access key",
                "short_message": "Umbra linked a geo-anomalous cloud login with new access key creation.",
                "log_type": "correlated",
                "severity": "high",
                "summary": (
                    f"Principal {principal} performed a cloud console login from an unusual region, "
                    f"followed by access key creation within ~{time_window_minutes} minutes."
                ),
                "description": (
                    "This pattern is consistent with an attacker obtaining cloud console access from a "
                    "new/rare location and immediately establishing persistent credentials. "
                    "Investigate the actor, revoke keys, and review additional activity."
                ),
                "tags": [
                    "correlated",
                    "cloud",
                    "persistence",
                    "iam",
                ],
                "mitre": _collect_mitre([lg_a, ke_a]),
                "frameworks": {},
                "event": {
                    "correlated_principal": principal,
                    "time_window_minutes": time_window_minutes,
                    "login_alert_id": lg_a.get("id") or lg_a.get("rule_id"),
                    "access_key_alert_id": ke_a.get("id") or ke_a.get("rule_id"),
                    "login_event": lg_a.get("event", {}),
                    "key_event": ke_a.get("event", {}),
                },
                "anomaly": {
                    "signals": [
                        "Cross-log inference: geo-anomalous login followed by key creation.",
                        "Behavior consistent with cloud account takeover and persistence.",
                    ]
                },
            }
            correlated.append(meta_alert)
            break

    # -------------------------------------------------------------------
    # Pattern 3: Infostealer credential clustering (device / account / domains)
    # -------------------------------------------------------------------
    # Thresholds tuned for lab-sized data (you can tweak later)
    INF_MIN_USERS_PER_HOST = 3   # multi-accounts from same device
    INF_MIN_HOSTS_PER_USER = 2   # same account on >=2 hosts
    INF_MIN_DOMAINS_PER_USER = 3 # same login across >=3 domains

    # Filter down to infostealer alerts
    infostealer_items = [
        e for e in enriched
        if e["alert"].get("log_type") == "infostealer"
        or _has_tag(e["alert"], "infostealer")
    ]

    if infostealer_items:
        by_host: Dict[str, List[Dict[str, Any]]] = {}
        by_user: Dict[str, List[Dict[str, Any]]] = {}

        # Build host/user groupings
        for e in infostealer_items:
            a = e["alert"]
            ev = a.get("event", {}) or {}

            host = (
                ev.get("host")
                or ev.get("pc")
                or ev.get("hostname")
                or ev.get("device")
            )
            user = (
                ev.get("user")
                or ev.get("login")
                or ev.get("account")
                or ev.get("principal")
            )

            if host:
                by_host.setdefault(str(host), []).append(e)
            if user:
                by_user.setdefault(str(user), []).append(e)

        # ---- 3A: Multiple accounts from same device (host) ----
        for host, items in by_host.items():
            # Distinct users observed in these infostealer logs
            distinct_users = set()
            for e in items:
                ev = (e["alert"].get("event", {}) or {})
                u = (
                    ev.get("user")
                    or ev.get("login")
                    or ev.get("account")
                    or ev.get("principal")
                )
                if u:
                    distinct_users.add(str(u))

            if len(distinct_users) < INF_MIN_USERS_PER_HOST:
                continue

            # Choose earliest timestamp as reference
            ts_candidates = [x["ts"] for x in items if isinstance(x["ts"], datetime)]
            base_ts = (min(ts_candidates).isoformat() if ts_candidates else "NA")

            child_alerts = [x["alert"] for x in items]
            meta_id = f"CORR-INFOSTEALER-MULTI-ACCOUNTS-{host}-{base_ts}"

            meta_alert: Alert = {
                "id": meta_id,
                "rule_id": "CORR_INFOSTEALER_01",
                "title": "[HIGH] Infostealer device harvesting multiple accounts",
                "short_message": (
                    "Umbra clustered multiple stolen accounts originating from the same device."
                ),
                "log_type": "correlated",
                "severity": "high",
                "summary": (
                    f"Device `{host}` appears in infostealer logs tied to at least "
                    f"{len(distinct_users)} distinct accounts. This strongly suggests an "
                    f"infostealer or credential-harvesting implant on that host."
                ),
                "description": (
                    "Umbra observed multiple stolen logins from a single endpoint. "
                    "In typical environments, one user corresponds to a small set of logins. "
                    "When many unrelated accounts are harvested from one host, it usually "
                    "indicates the machine has been infected with an infostealer.\n\n"
                    "Treat this endpoint as compromised, isolate it, reimage if necessary, "
                    "and rotate credentials for affected accounts."
                ),
                "tags": [
                    "correlated",
                    "infostealer",
                    "credential_access",
                    "multi-account",
                ],
                "mitre": _collect_mitre(child_alerts),
                "frameworks": {},
                "event": {
                    "correlated_type": "infostealer_multi_accounts_same_device",
                    "host": host,
                    "distinct_users": sorted(distinct_users),
                    "num_distinct_users": len(distinct_users),
                    "child_alert_ids": [
                        a.get("id") or a.get("rule_id") for a in child_alerts
                    ],
                },
                "anomaly": {
                    "signals": [
                        "Multiple unrelated accounts stolen from same endpoint.",
                        "Pattern consistent with an infostealer infection on the device.",
                    ]
                },
            }
            correlated.append(meta_alert)

        # ---- 3B: Same account observed on multiple hosts ----
        for user, items in by_user.items():
            # Distinct hosts that saw this account stolen
            distinct_hosts = set()
            for e in items:
                ev = (e["alert"].get("event", {}) or {})
                h = (
                    ev.get("host")
                    or ev.get("pc")
                    or ev.get("hostname")
                    or ev.get("device")
                )
                if h:
                    distinct_hosts.add(str(h))

            if len(distinct_hosts) < INF_MIN_HOSTS_PER_USER:
                continue

            ts_candidates = [x["ts"] for x in items if isinstance(x["ts"], datetime)]
            base_ts = (min(ts_candidates).isoformat() if ts_candidates else "NA")

            child_alerts = [x["alert"] for x in items]
            meta_id = f"CORR-INFOSTEALER-ACCOUNT-MULTI-HOSTS-{user}-{base_ts}"

            meta_alert: Alert = {
                "id": meta_id,
                "rule_id": "CORR_INFOSTEALER_02",
                "title": "[CRITICAL] Same account stolen from multiple hosts",
                "short_message": (
                    "Umbra detected the same account credentials harvested on multiple endpoints."
                ),
                "log_type": "correlated",
                "severity": "critical",
                "summary": (
                    f"Account `{user}` appears in infostealer dumps from {len(distinct_hosts)} "
                    f"distinct hosts. This suggests either widespread compromise or reuse of "
                    f"the same credentials across many infected devices."
                ),
                "description": (
                    "When the same account is observed in multiple infostealer logs, it often "
                    "means that the credentials are reused across several machines, or that the "
                    "account belongs to an administrator or shared service targeted at scale.\n\n"
                    "Immediately rotate this account's credentials, inspect each affected host, "
                    "and hunt for where these credentials are actively in use."
                ),
                "tags": [
                    "correlated",
                    "infostealer",
                    "credential_access",
                    "lateral_movement",
                ],
                "mitre": _collect_mitre(child_alerts),
                "frameworks": {},
                "event": {
                    "correlated_type": "infostealer_account_multiple_hosts",
                    "user": user,
                    "distinct_hosts": sorted(distinct_hosts),
                    "num_distinct_hosts": len(distinct_hosts),
                    "child_alert_ids": [
                        a.get("id") or a.get("rule_id") for a in child_alerts
                    ],
                },
                "anomaly": {
                    "signals": [
                        "Same account credentials harvested on multiple hosts.",
                        "Pattern consistent with shared or reused credentials across compromised endpoints.",
                    ]
                },
            }
            correlated.append(meta_alert)

        # ---- 3C: Same account reused across multiple domains ----
        for user, items in by_user.items():
            distinct_domains = set()
            for e in items:
                ev = (e["alert"].get("event", {}) or {})
                d = (
                    ev.get("domain")
                    or ev.get("url_domain")
                    or ev.get("site")
                )
                if d:
                    distinct_domains.add(str(d))

            if len(distinct_domains) < INF_MIN_DOMAINS_PER_USER:
                continue

            ts_candidates = [x["ts"] for x in items if isinstance(x["ts"], datetime)]
            base_ts = (min(ts_candidates).isoformat() if ts_candidates else "NA")

            child_alerts = [x["alert"] for x in items]
            meta_id = f"CORR-INFOSTEALER-PASSWORD-REUSE-{user}-{base_ts}"

            meta_alert: Alert = {
                "id": meta_id,
                "rule_id": "CORR_INFOSTEALER_03",
                "title": "[HIGH] Credential reuse across multiple domains",
                "short_message": (
                    "Umbra detected the same account credentials reused across multiple sites/domains in infostealer logs."
                ),
                "log_type": "correlated",
                "severity": "high",
                "summary": (
                    f"Account `{user}` appears in infostealer entries tied to at least "
                    f"{len(distinct_domains)} distinct domains. This signals risky password reuse "
                    f"and broad exposure if those credentials are compromised."
                ),
                "description": (
                    "Password reuse dramatically increases blast radius: once one site is compromised, "
                    "attackers can pivot into others using the same credentials. Infostealer dumps "
                    "make this even worse by handing out credential/URL pairs in bulk.\n\n"
                    "Force password resets for this account, monitor for login attempts to the "
                    "affected domains, and educate the user on password hygiene and MFA."
                ),
                "tags": [
                    "correlated",
                    "infostealer",
                    "credential_access",
                    "password_reuse",
                ],
                "mitre": _collect_mitre(child_alerts),
                "frameworks": {},
                "event": {
                    "correlated_type": "infostealer_password_reuse_across_domains",
                    "user": user,
                    "distinct_domains": sorted(distinct_domains),
                    "num_distinct_domains": len(distinct_domains),
                    "child_alert_ids": [
                        a.get("id") or a.get("rule_id") for a in child_alerts
                    ],
                },
                "anomaly": {
                    "signals": [
                        "Same account credentials reused across multiple domains in stealer logs.",
                        "Pattern consistent with unsafe password reuse and broad credential exposure.",
                    ]
                },
            }
            correlated.append(meta_alert)

        # -------------------------------------------------------------------
        # Pattern 4: Domain + stealer_log_id incident roll-up
        #      (Telefonica-style incident summary)
        # -------------------------------------------------------------------
        buckets: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for e in infostealer_items:
            a = e["alert"]
            ev = a.get("event", {}) or {}

            domain = str(
                ev.get("domain")
                or ev.get("url_domain")
                or ev.get("site")
                or "unknown"
            ).lower()

            stealer_id = str(
                ev.get("stealer_log_id")
                or ev.get("Stealer log ID")
                or ev.get("source")
                or "unknown"
            )

            key = (domain, stealer_id)
            buckets.setdefault(key, []).append(e)

        for (domain, stealer_id), bucket in buckets.items():
            if domain == "unknown":
                continue  # skip junk groupings

            urls = set()
            users = set()
            emails = set()
            hosts = set()
            ips = set()
            oss = set()
            first_ts: Optional[datetime] = None
            last_ts: Optional[datetime] = None

            for e in bucket:
                a = e["alert"]
                ev = a.get("event", {}) or {}

                # timestamps
                ts = e["ts"]
                if isinstance(ts, datetime):
                    if first_ts is None or ts < first_ts:
                        first_ts = ts
                    if last_ts is None or ts > last_ts:
                        last_ts = ts

                if ev.get("url"):
                    urls.add(str(ev["url"]))
                if ev.get("login"):
                    users.add(str(ev["login"]))
                if ev.get("user"):
                    users.add(str(ev["user"]))
                if ev.get("Emails") or ev.get("emails"):
                    val = ev.get("Emails") or ev.get("emails")
                    if isinstance(val, str):
                        for piece in val.split(","):
                            piece = piece.strip()
                            if piece:
                                emails.add(piece)
                if ev.get("host") or ev.get("pc"):
                    hosts.add(str(ev.get("host") or ev.get("pc")))
                if ev.get("ip") or ev.get("source_ip"):
                    ips.add(str(ev.get("ip") or ev.get("source_ip")))
                if ev.get("os"):
                    oss.add(str(ev["os"]))

            url_count = len(urls)
            user_count = len(users)
            email_count = len(emails)

            # severity heuristic
            if user_count >= 10 or url_count >= 15:
                sev = "critical"
            elif user_count >= 3 or url_count >= 5:
                sev = "high"
            else:
                sev = "medium"

            host_list = ", ".join(sorted(hosts)) or "unknown host"
            ip_list = ", ".join(sorted(ips)) or "unknown IP"
            os_list = ", ".join(sorted(oss)) or "unknown OS"

            time_range_str = ""
            if first_ts and last_ts:
                if first_ts.date() == last_ts.date():
                    time_range_str = first_ts.date().isoformat()
                else:
                    time_range_str = f"{first_ts.date().isoformat()} – {last_ts.date().isoformat()}"

            child_alerts = [x["alert"] for x in bucket]
            meta_id = f"CORR-INFOSTEALER-INCIDENT-{domain}-{stealer_id}"
            title = f"[{sev.upper()}] Infostealer credential dump for {domain}"

            summary_parts = [
                f"Domain: {domain}",
                f"Accounts exposed: {user_count}",
                f"URLs affected: {url_count}",
            ]
            if time_range_str:
                summary_parts.append(f"Compromise window: {time_range_str}")

            summary = " | ".join(summary_parts)

            description_lines = [
                f"Umbra clustered an infostealer credential incident for **{domain}** using stealer log ID `{stealer_id}`.",
                "",
                f"- **Compromised accounts (logins/users):** {', '.join(sorted(users)) or 'unknown'}",
                f"- **Compromised emails:** {', '.join(sorted(emails)) or 'unknown'}",
                f"- **Number of affected URLs/services:** {url_count}",
            ]
            if urls:
                description_lines.append("- **Affected URLs / services:**")
                for u in sorted(urls):
                    description_lines.append(f"  - {u}")
            description_lines.extend(
                [
                    f"- **Compromised host(s):** {host_list}",
                    f"- **Compromised IP(s):** {ip_list}",
                    f"- **Observed OS:** {os_list}",
                    "",
                    "This is an incident-level roll-up synthesized from individual infostealer rows. "
                    "Use it as the starting point for containment and response.",
                ]
            )

            meta_alert: Alert = {
                "id": meta_id,
                "rule_id": "CORR_INFOSTEALER_04",
                "title": title,
                "short_message": f"Infostealer log `{stealer_id}` leaked credentials for {domain}.",
                "log_type": "correlated",
                "severity": sev,
                "summary": summary,
                "description": "\n".join(description_lines),
                "tags": [
                    "correlated",
                    "incident",
                    "infostealer",
                    "credential_access",
                ],
                "mitre": (
                    _collect_mitre(child_alerts)
                    + ["T1555", "T1552"]  # credentials from password stores / unsecured creds
                ),
                "frameworks": {},
                "event": {
                    "correlated_type": "infostealer_domain_incident",
                    "domain": domain,
                    "stealer_log_id": stealer_id,
                    "account_count": user_count,
                    "url_count": url_count,
                    "email_count": email_count,
                    "hosts": sorted(hosts),
                    "ips": sorted(ips),
                    "oses": sorted(oss),
                    "first_seen": first_ts.isoformat() if isinstance(first_ts, datetime) else None,
                    "last_seen": last_ts.isoformat() if isinstance(last_ts, datetime) else None,
                    "sample_urls": sorted(urls)[:20],
                },
                "anomaly": {
                    "signals": [
                        "Multiple infostealer rows for same domain + stealer log ID clustered into a single incident.",
                        "Pattern consistent with targeted credential compromise for this organization.",
                    ]
                },
            }
            correlated.append(meta_alert)

    return correlated
