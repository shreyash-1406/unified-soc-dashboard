import json
import os
from datetime import datetime, timedelta

import pytest

from soc.app import create_app
from soc.correlate import build_incidents, dedupe, is_internal, score_alerts
from soc.models import Alert, normalise_severity, parse_time
from soc.parsers import detect_format, parse_auth_line, parse_file, parse_lines

ROOT = os.path.join(os.path.dirname(__file__), "..", "sample_data")
T0 = datetime(2026, 10, 22, 9, 0, 0)


def load_all():
    alerts = []
    for f in ("auth.log", "suricata_eve.json", "wazuh_alerts.json"):
        alerts += parse_file(os.path.join(ROOT, f))[0]
    alerts, _ = dedupe(alerts)
    return score_alerts(alerts, ["web-01", "db-01", "dc-01"])


# ---------------- parsing ----------------

def test_detect_formats():
    assert detect_format('{"rule": {"level": 3}, "agent": {"name": "a"}}') == "wazuh"
    assert detect_format('{"event_type": "alert"}') == "suricata"
    assert detect_format('{"title": "x"}') == "generic"
    assert detect_format("Oct 22 09:12:00 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2") == "linux_auth"
    assert detect_format("garbage") == "unknown"


def test_auth_lines():
    a = parse_auth_line("Oct 22 09:12:00 web-01 sshd[1]: Failed password for invalid user bob from 203.0.113.9 port 22 ssh2", 2026)
    assert (a.title, a.user, a.src_ip, a.host) == ("SSH failed password", "bob", "203.0.113.9", "web-01")
    assert a.mitre_technique == "T1110"
    s = parse_auth_line("Oct 22 09:17:02 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", 2026)
    assert s.user == "deploy" and s.severity == "medium" and s.mitre_tactic == "Privilege Escalation"
    assert parse_auth_line("Oct 22 09:00:00 web-01 cron[5]: session opened", 2026) is None


def test_suricata_skips_non_alerts_and_bad_lines():
    lines = ['{"event_type": "flow"}', "not json",
             '{"timestamp": "2026-10-22T09:00:00.0+0530", "event_type": "alert", "src_ip": "1.1.1.1", '
             '"alert": {"signature": "ET SCAN test", "severity": 1}}']
    alerts, stats = parse_lines(lines, "suricata")
    assert len(alerts) == 1 and stats["skipped"] == 2
    assert alerts[0].severity == "high" and alerts[0].mitre_tactic == "Discovery"


def test_helpers():
    assert normalise_severity(13) == "critical" and normalise_severity(2) == "low"
    assert normalise_severity("warning") == "medium" and normalise_severity("???") == "medium"
    assert parse_time("2026-10-22T09:00:00.000+0530") == datetime(2026, 10, 22, 9, 0)
    assert is_internal("10.1.2.3") and is_internal("192.168.0.1") and is_internal("172.20.0.1")
    assert not is_internal("203.0.113.5") and not is_internal("172.2.0.1") and not is_internal("bad")


# ---------------- correlation ----------------

def test_dedupe_only_exact_duplicates():
    a = Alert(T0, "x", "t", "low", src_ip="1.1.1.1", user="u")
    b = Alert(T0, "x", "t", "low", src_ip="1.1.1.1", user="u")
    c = Alert(T0 + timedelta(seconds=1), "x", "t", "low", src_ip="1.1.1.1", user="u")
    out, dupes = dedupe([a, b, c])
    assert len(out) == 2 and dupes == 1


def test_sample_scenario_finds_the_three_attacks():
    incidents = build_incidents(load_all())
    by_entity = {i.entity: i for i in incidents}

    bf = by_entity["ip:203.0.113.45"]
    names = [p["name"] for p in bf.patterns]
    assert "Brute force followed by successful login" in names
    assert "Login followed by privilege use" in names        # sudo/crontab attached via session
    assert bf.severity == "critical" and "deploy" in bf.users

    assert "Possible command-and-control or data exfiltration" in [p["name"] for p in by_entity["ip:10.0.2.15"].patterns]
    assert "Scan followed by exploitation attempt" in [p["name"] for p in by_entity["ip:198.51.100.23"].patterns]

    # the top 3 incidents are the real attacks
    assert {i.entity for i in incidents[:3]} == {"ip:203.0.113.45", "ip:10.0.2.15", "ip:198.51.100.23"}
    # a user mistyping a password internally is not an incident
    assert "ip:10.0.1.22" not in by_entity
    # strong noise reduction
    assert len(incidents) <= 8


def test_incident_ids_are_stable():
    ids1 = [i.id for i in build_incidents(load_all())]
    ids2 = [i.id for i in build_incidents(load_all())]
    assert ids1 == ids2


def test_failed_logins_alone_are_not_success():
    alerts = [Alert(T0 + timedelta(seconds=i), "linux_auth", "SSH failed password", "low",
                    src_ip="203.0.113.7", user="root", host="h", mitre_technique="T1110",
                    mitre_tactic="Credential Access") for i in range(12)]
    score_alerts(alerts)
    (inc,) = build_incidents(alerts)
    names = [p["name"] for p in inc.patterns]
    assert "Brute force attempt" in names
    assert "Brute force followed by successful login" not in names


# ---------------- web app ----------------

@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "t.db"), use_ai=False, critical_hosts=["web-01"])
    app.config["TESTING"] = True
    return app.test_client()


def test_web_flow(client):
    assert b"No alerts yet" in client.get("/").data
    client.post("/demo")
    page = client.get("/").data
    assert b"Brute force followed by successful login" in page
    incidents = client.get("/api/incidents").get_json()
    iid = incidents[0]["id"]
    assert client.get(f"/incidents/{iid}").status_code == 200
    client.post(f"/incidents/{iid}", data={"status": "investigating", "note": "Called the server owner"})
    detail = client.get(f"/incidents/{iid}").data
    assert b"Called the server owner" in detail
    # AI disabled -> falls back gracefully
    r = client.post(f"/incidents/{iid}/triage", follow_redirects=True)
    assert r.status_code == 200
    assert client.get("/incidents/NOPE").status_code == 404


def test_demo_is_idempotent(client):
    client.post("/demo")
    first = len(client.get("/api/incidents").get_json())
    client.post("/demo")                                    # same files again -> all duplicates
    assert len(client.get("/api/incidents").get_json()) == first


def test_api_ingest_and_filters(client):
    body = "\n".join(json.dumps({"timestamp": "2026-10-22T10:00:00", "title": "Malware detected <b>x</b>",
                                 "severity": "critical", "host": "pc-1", "src_ip": "10.9.9.9"}) for _ in range(1))
    r = client.post("/api/ingest?format=generic", data=body)
    assert r.get_json()["stored"] == 1
    assert client.post("/api/ingest?format=nope", data=body).status_code == 400
    page = client.get("/alerts?severity=critical&q=malware").data
    assert b"Malware detected &lt;b&gt;x&lt;/b&gt;" in page          # escaped
    assert b"<b>x</b>" not in page


def test_upload_and_reset(client):
    from io import BytesIO
    data = open(os.path.join(ROOT, "auth.log"), "rb").read()
    r = client.post("/ingest", data={"file": (BytesIO(data), "auth.log"), "format": "auto"},
                    content_type="multipart/form-data", follow_redirects=True)
    assert b"detected linux_auth" in r.data
    client.post("/reset")
    assert b"No alerts yet" in client.get("/").data
