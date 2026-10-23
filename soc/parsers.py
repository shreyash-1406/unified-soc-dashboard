"""
Parsers: one tool's raw log record -> a normalised Alert.

Supported sources
    wazuh       Wazuh manager alerts.json (one JSON object per line)
    suricata    Suricata eve.json, records with event_type == "alert"
    linux_auth  /var/log/auth.log style sshd and sudo lines
    generic     any JSON with timestamp/title/severity fields

`parse_file` auto-detects the source from the first non-empty line.
"""

import json
import re
from datetime import datetime

from .models import Alert, normalise_severity, parse_time

# A small MITRE ATT&CK map used when a tool doesn't provide one
KEYWORD_MITRE = [
    (re.compile(r"brute|multiple .*fail|authentication fail|failed password", re.I), "T1110", "Credential Access"),
    (re.compile(r"scan|nmap|recon", re.I), "T1046", "Discovery"),
    (re.compile(r"sudo|privilege|root", re.I), "T1548", "Privilege Escalation"),
    (re.compile(r"sql injection|xss|web attack|exploit", re.I), "T1190", "Initial Access"),
    (re.compile(r"malware|trojan|ransom|virus", re.I), "T1204", "Execution"),
    (re.compile(r"c2|command and control|beacon|callback", re.I), "T1071", "Command and Control"),
    (re.compile(r"exfil|large upload|data transfer", re.I), "T1041", "Exfiltration"),
    (re.compile(r"accepted password|successful login|logged in", re.I), "T1078", "Initial Access"),
]


def guess_mitre(text: str):
    for pattern, technique, tactic in KEYWORD_MITRE:
        if pattern.search(text or ""):
            return technique, tactic
    return "", ""


def _category(text: str) -> str:
    t = (text or "").lower()
    if any(k in t for k in ("login", "password", "auth", "ssh", "sudo")):
        return "authentication"
    if any(k in t for k in ("scan", "traffic", "dns", "port", "c2", "beacon")):
        return "network"
    if any(k in t for k in ("malware", "trojan", "virus", "ransom")):
        return "malware"
    if any(k in t for k in ("sql", "xss", "web", "http")):
        return "web"
    return "other"


# ---------------------------------------------------------------------------
# Wazuh
# ---------------------------------------------------------------------------

def parse_wazuh(rec: dict) -> Alert:
    rule = rec.get("rule", {})
    data = rec.get("data", {})
    title = rule.get("description", "Wazuh alert")
    mitre = rule.get("mitre", {})
    technique = (mitre.get("id") or [""])[0]
    tactic = (mitre.get("tactic") or [""])[0]
    if not technique:
        technique, tactic = guess_mitre(title)
    return Alert(
        timestamp=parse_time(rec.get("timestamp", "")),
        source="wazuh",
        title=title,
        severity=normalise_severity(int(rule.get("level", 5))),
        src_ip=data.get("srcip", ""),
        dest_ip=data.get("dstip", ""),
        host=rec.get("agent", {}).get("name", ""),
        user=data.get("dstuser", "") or data.get("srcuser", ""),
        category=_category(" ".join(rule.get("groups", [])) + " " + title),
        mitre_technique=technique,
        mitre_tactic=tactic,
        raw=rec,
    )


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

SURICATA_SEVERITY = {1: "high", 2: "medium", 3: "low"}


def parse_suricata(rec: dict) -> Alert:
    alert = rec.get("alert", {})
    title = alert.get("signature", "Suricata alert")
    technique, tactic = guess_mitre(title + " " + alert.get("category", ""))
    return Alert(
        timestamp=parse_time(rec.get("timestamp", "")),
        source="suricata",
        title=title,
        severity=SURICATA_SEVERITY.get(alert.get("severity", 2), "medium"),
        src_ip=rec.get("src_ip", ""),
        dest_ip=rec.get("dest_ip", ""),
        host=rec.get("host", "") or rec.get("in_iface", ""),
        category=_category(title + " " + alert.get("category", "")) or "network",
        mitre_technique=technique,
        mitre_tactic=tactic,
        raw=rec,
    )


# ---------------------------------------------------------------------------
# Linux auth.log
# ---------------------------------------------------------------------------

AUTH_LINE = re.compile(
    r"^(?P<ts>\S+|\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SUDO = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")


def parse_auth_line(line: str, year: int = None):
    m = AUTH_LINE.match(line.strip())
    if not m:
        return None
    msg, host, proc = m.group("msg"), m.group("host"), m.group("proc")
    ts_text = m.group("ts")
    try:
        ts = datetime.strptime(f"{year or datetime.now().year} {ts_text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        ts = parse_time(ts_text)

    def make(title, severity, user="", ip=""):
        technique, tactic = guess_mitre(title)
        return Alert(timestamp=ts, source="linux_auth", title=title, severity=severity,
                     src_ip=ip, host=host, user=user, category="authentication",
                     mitre_technique=technique, mitre_tactic=tactic, raw={"line": line.strip()})

    if (f := FAILED.search(msg)):
        return make("SSH failed password", "low", f.group("user"), f.group("ip"))
    if (a := ACCEPTED.search(msg)):
        return make("SSH successful login", "low", a.group("user"), a.group("ip"))
    if (i := INVALID.search(msg)):
        return make("SSH login attempt for invalid user", "low", i.group("user"), i.group("ip"))
    if proc == "sudo" and (s := SUDO.search(msg)):
        sev = "medium" if s.group("user") != "root" else "low"
        return make(f"sudo command: {s.group('cmd')[:80]}", sev, s.group("user"))
    return None


# ---------------------------------------------------------------------------
# Generic JSON
# ---------------------------------------------------------------------------

def parse_generic(rec: dict) -> Alert:
    title = rec.get("title") or rec.get("message") or rec.get("name") or "Alert"
    technique, tactic = guess_mitre(title)
    return Alert(
        timestamp=parse_time(rec.get("timestamp") or rec.get("@timestamp") or ""),
        source=rec.get("source", "generic"),
        title=title,
        severity=normalise_severity(rec.get("severity", "medium")),
        src_ip=rec.get("src_ip", ""),
        dest_ip=rec.get("dest_ip", ""),
        host=rec.get("host", ""),
        user=rec.get("user", ""),
        category=rec.get("category") or _category(title),
        mitre_technique=rec.get("mitre_technique") or technique,
        mitre_tactic=rec.get("mitre_tactic") or tactic,
        raw=rec,
    )


# ---------------------------------------------------------------------------
# Detection of format + file parsing
# ---------------------------------------------------------------------------

def detect_format(first_line: str) -> str:
    line = first_line.strip()
    if line.startswith("{"):
        try:
            rec = json.loads(line)
        except ValueError:
            return "unknown"
        if "rule" in rec and "agent" in rec:
            return "wazuh"
        if rec.get("event_type"):
            return "suricata"
        return "generic"
    if AUTH_LINE.match(line):
        return "linux_auth"
    return "unknown"


def parse_lines(lines, fmt: str = "auto"):
    """Returns (alerts, stats). Bad lines are counted and skipped, never fatal."""
    lines = [l for l in lines if l.strip()]
    if not lines:
        return [], {"format": fmt, "parsed": 0, "skipped": 0}
    if fmt == "auto":
        fmt = detect_format(lines[0])

    alerts, skipped = [], 0
    for line in lines:
        try:
            if fmt == "linux_auth":
                a = parse_auth_line(line)
            else:
                rec = json.loads(line)
                if fmt == "wazuh":
                    a = parse_wazuh(rec)
                elif fmt == "suricata":
                    a = parse_suricata(rec) if rec.get("event_type") == "alert" else None
                elif fmt == "generic":
                    a = parse_generic(rec)
                else:
                    a = None
        except (ValueError, TypeError, AttributeError):
            a = None
        if a is None:
            skipped += 1
        else:
            alerts.append(a)
    return alerts, {"format": fmt, "parsed": len(alerts), "skipped": skipped}


def parse_file(path: str, fmt: str = "auto"):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh.readlines(), fmt)
