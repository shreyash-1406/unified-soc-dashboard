"""
Common alert schema.

Every security tool logs alerts in its own format. The dashboard converts all
of them into this one `Alert` shape (loosely based on the Elastic Common
Schema) so they can be searched, scored and correlated together.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib

SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 10}


@dataclass
class Alert:
    timestamp: datetime
    source: str                 # wazuh, suricata, windows, linux-auth
    title: str
    severity: str               # low / medium / high / critical
    src_ip: str = ""
    dest_ip: str = ""
    host: str = ""
    user: str = ""
    category: str = ""          # authentication, network, malware, policy...
    mitre_technique: str = ""   # e.g. T1110 (Brute Force)
    mitre_tactic: str = ""
    raw: dict = field(default_factory=dict)
    risk_score: int = 0
    status: str = "new"         # new / investigating / closed / false_positive

    @property
    def fingerprint(self) -> str:
        """Identical alert delivered twice (same tool, second, endpoints, user, title) = duplicate."""
        key = f"{self.source}|{self.title}|{self.src_ip}|{self.dest_ip}|{self.host}|{self.user}|" \
              f"{self.timestamp.isoformat(timespec='seconds')}|{self.raw.get('dest_port', '')}"
        return hashlib.sha1(key.encode()).hexdigest()[:16]

    def to_dict(self):
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["fingerprint"] = self.fingerprint
        return d


def normalise_severity(value) -> str:
    """Map numeric levels and vendor words onto our four severities."""
    if isinstance(value, (int, float)):
        n = float(value)
        if n >= 12:
            return "critical"
        if n >= 8:
            return "high"
        if n >= 4:
            return "medium"
        return "low"
    text = str(value).strip().lower()
    aliases = {
        "info": "low", "informational": "low", "notice": "low", "warning": "medium",
        "warn": "medium", "moderate": "medium", "error": "high", "severe": "high",
        "emergency": "critical", "alert": "critical", "crit": "critical",
    }
    text = aliases.get(text, text)
    return text if text in SEVERITIES else "medium"


def parse_time(value) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    text = str(value).replace("Z", "+00:00")
    # Suricata uses +0000 without a colon
    if len(text) > 5 and text[-5] in "+-" and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return datetime.now()
