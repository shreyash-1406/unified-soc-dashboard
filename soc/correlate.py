"""
Scoring, de-duplication and correlation.

Analysts drown in single alerts. This module turns them into a short list of
incidents worth looking at:

1. De-duplicate: identical alerts from the same tool within a minute collapse.
2. Risk score each alert (0-100): severity, MITRE tactic, how often the source
   repeats, and whether the target host is critical.
3. Group alerts into incidents by entity (source IP, or host+user when there
   is no IP) inside a time window.
4. Apply correlation rules that look for attack patterns across alerts, e.g.
   many failed logins followed by a success from the same IP, which is far
   more serious than either alert alone.
"""

import hashlib
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .models import SEVERITIES, SEVERITY_WEIGHT

WINDOW = timedelta(minutes=30)

# Later stages of an attack matter more than early noise
TACTIC_WEIGHT = {
    "Discovery": 0, "Reconnaissance": 0, "Initial Access": 8, "Execution": 10,
    "Credential Access": 6, "Privilege Escalation": 12, "Persistence": 10,
    "Lateral Movement": 14, "Command and Control": 15, "Exfiltration": 18, "Impact": 18,
}

INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fe80::/10")]


def is_internal(ip: str) -> bool:
    """RFC1918, loopback and link-local addresses count as internal (your own network)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS if addr.version == net.version)


@dataclass
class Incident:
    id: str
    entity: str
    title: str
    severity: str
    risk: int
    first_seen: str
    last_seen: str
    alert_count: int
    sources: list
    hosts: list
    users: list
    techniques: list
    tactics: list
    patterns: list = field(default_factory=list)       # correlation rules that fired
    alert_ids: list = field(default_factory=list)
    summary: str = ""
    summary_source: str = "template"


def dedupe(alerts):
    seen, out, dupes = set(), [], 0
    for a in sorted(alerts, key=lambda x: x.timestamp):
        fp = a.fingerprint
        if fp in seen:
            dupes += 1
            continue
        seen.add(fp)
        out.append(a)
    return out, dupes


def score_alerts(alerts, critical_hosts=()):
    """Sets alert.risk_score in place."""
    critical = {h.lower() for h in critical_hosts}
    per_source = Counter(a.src_ip for a in alerts if a.src_ip)
    for a in alerts:
        score = SEVERITY_WEIGHT[a.severity] * 6                     # 6..60
        score += TACTIC_WEIGHT.get(a.mitre_tactic, 0)               # 0..18
        if a.src_ip and per_source[a.src_ip] >= 10:
            score += 8                                              # noisy, persistent source
        elif a.src_ip and per_source[a.src_ip] >= 3:
            score += 4
        if a.host and a.host.lower() in critical:
            score += 12
        if a.src_ip and not is_internal(a.src_ip) and a.category == "authentication":
            score += 4                                              # internet-facing auth attempts
        a.risk_score = min(score, 100)
    return alerts


def _entity(a):
    if a.src_ip:
        return f"ip:{a.src_ip}"
    if a.host and a.user:
        return f"user:{a.user}@{a.host}"
    if a.host:
        return f"host:{a.host}"
    return "unknown"


# ---------------------------------------------------------------------------
# Correlation rules. Each takes the alerts of one incident (time-ordered) and
# returns a (name, description, severity, bonus) tuple or None.
# ---------------------------------------------------------------------------

def rule_bruteforce_then_success(alerts):
    fails = [a for a in alerts if a.mitre_technique == "T1110" or "failed" in a.title.lower()
             or "invalid user" in a.title.lower()]
    success = [a for a in alerts if "successful login" in a.title.lower() or "accepted" in a.title.lower()]
    if len(fails) >= 5 and success and success[-1].timestamp >= fails[0].timestamp:
        users = sorted({a.user for a in success if a.user})
        return ("Brute force followed by successful login",
                f"{len(fails)} failed logins, then a successful login"
                f"{' as ' + ', '.join(users) if users else ''}. Possible compromised account.",
                "critical", 30)
    return None


def rule_bruteforce(alerts):
    fails = [a for a in alerts if "failed" in a.title.lower() or "invalid user" in a.title.lower()
             or a.mitre_technique == "T1110"]
    users = {a.user for a in fails if a.user}
    if len(fails) >= 10:
        kind = "Password spraying" if len(users) >= 5 else "Brute force"
        return (f"{kind} attempt",
                f"{len(fails)} failed authentication attempts against {len(users) or 'unknown'} account(s).",
                "high", 12)
    return None


def rule_scan_then_exploit(alerts):
    tactics = [a.mitre_tactic for a in alerts]
    if "Discovery" in tactics and ("Initial Access" in tactics or "Execution" in tactics):
        first_scan = next(a.timestamp for a in alerts if a.mitre_tactic == "Discovery")
        later = [a for a in alerts if a.mitre_tactic in ("Initial Access", "Execution")
                 and a.timestamp >= first_scan]
        if later:
            return ("Scan followed by exploitation attempt",
                    "The same source scanned the network and then triggered exploit or web attack signatures.",
                    "high", 15)
    return None


def rule_c2_or_exfil(alerts):
    tactics = {a.mitre_tactic for a in alerts}
    if "Command and Control" in tactics or "Exfiltration" in tactics:
        return ("Possible command-and-control or data exfiltration",
                "Traffic matched C2 or exfiltration signatures. Check the host for compromise.",
                "critical", 25)
    return None


def rule_privilege_after_login(alerts):
    logins = [a for a in alerts if "successful login" in a.title.lower() and not is_internal(a.src_ip)]
    priv = [a for a in alerts if a.mitre_tactic in ("Privilege Escalation", "Persistence")]
    if logins and priv and priv[-1].timestamp >= logins[0].timestamp:
        return ("Login followed by privilege use",
                "A login from outside the network was followed by privileged commands or persistence "
                "changes in the same session.", "high", 12)
    return None


RULES = [rule_bruteforce_then_success, rule_bruteforce, rule_scan_then_exploit,
         rule_c2_or_exfil, rule_privilege_after_login]


def attribute_sessions(alerts):
    """
    Host-only alerts (sudo, file changes) often carry a user but no IP.
    If that user logged in to that host from an IP shortly before, the
    activity belongs to the same session, so link it to that IP.
    Returns {alert index: entity}.
    """
    logins = {}                 # (user, host) -> (ip, time)
    entities = {}
    for idx, a in sorted(enumerate(alerts), key=lambda t: t[1].timestamp):
        key = (a.user, a.host)
        if a.src_ip and "successful login" in a.title.lower() or (a.src_ip and "authentication success" in a.title.lower()):
            logins[key] = (a.src_ip, a.timestamp)
        if not a.src_ip and a.user and key in logins:
            ip, when = logins[key]
            if a.timestamp - when <= WINDOW:
                entities[idx] = f"ip:{ip}"
                continue
        entities[idx] = _entity(a)
    return entities


def build_incidents(alerts):
    """Group alerts per entity into time windows and apply correlation rules."""
    entities = attribute_sessions(alerts)
    by_entity = defaultdict(list)
    for idx, a in enumerate(alerts):
        by_entity[entities[idx]].append((idx, a))

    incidents = []
    for entity, items in by_entity.items():
        items.sort(key=lambda t: t[1].timestamp)
        groups, current = [], [items[0]]
        for item in items[1:]:
            if item[1].timestamp - current[-1][1].timestamp <= WINDOW:
                current.append(item)
            else:
                groups.append(current)
                current = [item]
        groups.append(current)

        for g in groups:
            group_alerts = [a for _, a in g]
            patterns = [p for p in (rule(group_alerts) for rule in RULES) if p]
            # A single low alert with no pattern is noise, not an incident
            top_alert = max(group_alerts, key=lambda a: a.risk_score)
            worst = max(SEVERITIES.index(a.severity) for a in group_alerts)
            # Noise: nothing correlated and either only low alerts, or a couple of medium ones
            if not patterns and (worst == 0 or (len(group_alerts) < 3 and worst < SEVERITIES.index("high"))):
                continue

            sev_rank = max(SEVERITIES.index(a.severity) for a in group_alerts)
            for p in patterns:
                sev_rank = max(sev_rank, SEVERITIES.index(p[2]))
            risk = top_alert.risk_score + sum(p[3] for p in patterns) + min(len(group_alerts), 20) // 2
            title = patterns[0][0] if patterns else top_alert.title
            first, last = group_alerts[0].timestamp, group_alerts[-1].timestamp
            incidents.append(Incident(
                id=f"INC-{first:%m%d%H%M}-{hashlib.sha1(entity.encode()).hexdigest()[:4]}",
                entity=entity,
                title=title,
                severity=SEVERITIES[sev_rank],
                risk=min(risk, 100),
                first_seen=first.isoformat(),
                last_seen=last.isoformat(),
                alert_count=len(group_alerts),
                sources=sorted({a.source for a in group_alerts}),
                hosts=sorted({a.host for a in group_alerts if a.host}),
                users=sorted({a.user for a in group_alerts if a.user}),
                techniques=sorted({a.mitre_technique for a in group_alerts if a.mitre_technique}),
                tactics=sorted({a.mitre_tactic for a in group_alerts if a.mitre_tactic}),
                patterns=[{"name": p[0], "detail": p[1]} for p in patterns],
                alert_ids=[i for i, _ in g],
            ))

    incidents.sort(key=lambda i: (-i.risk, i.first_seen))
    return incidents


def template_summary(inc: Incident) -> str:
    """Analyst-style summary without an LLM."""
    who = inc.entity.split(":", 1)[-1]
    lines = [f"{inc.alert_count} alert(s) from {', '.join(inc.sources)} involving {who} "
             f"between {inc.first_seen[11:16]} and {inc.last_seen[11:16]}."]
    for p in inc.patterns:
        lines.append(p["detail"])
    steps = []
    if any("login" in p["name"].lower() for p in inc.patterns):
        steps.append("reset the affected account's password and review its recent sessions")
    if inc.entity.startswith("ip:") and not is_internal(who):
        steps.append(f"block {who} at the firewall if it is not a known partner")
    if any(t in inc.tactics for t in ("Command and Control", "Exfiltration")):
        steps.append("isolate the host and collect forensic data")
    if not steps:
        steps.append("confirm whether the activity is expected and close or escalate")
    lines.append("Suggested next steps: " + "; ".join(steps) + ".")
    return " ".join(lines)
