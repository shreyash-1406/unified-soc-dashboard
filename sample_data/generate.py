"""
Generates synthetic logs for the demo. Nothing here is real traffic.

All external IPs come from the reserved documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so they can never point at
a real system.

Scenario for the fictional company "Acme Corp" on one morning:
  1. 203.0.113.45 brute-forces SSH on web-01, gets in as "deploy",
     then runs sudo commands.                                   (auth.log + Wazuh)
  2. 198.51.100.23 port-scans the DMZ, then fires SQL injection
     and path traversal requests at the web server.             (Suricata)
  3. HR laptop 10.0.2.15 starts beaconing to 192.0.2.80.        (Suricata + Wazuh)
  4. Background noise: normal logins, low-level Wazuh events.

Usage:  python sample_data/generate.py           (writes into sample_data/)
"""

import json
import os
import random
from datetime import datetime, timedelta

OUT = os.path.dirname(os.path.abspath(__file__))
START = datetime(2026, 10, 22, 9, 0, 0)
rnd = random.Random(42)


def ts(minutes, seconds=0):
    return START + timedelta(minutes=minutes, seconds=seconds)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.000+0530")


def auth_log():
    lines = []
    users = ["admin", "root", "test", "oracle", "ubuntu", "deploy"]
    # 1. brute force from 203.0.113.45 against web-01
    for i in range(26):
        t = ts(12, i * 7)
        u = rnd.choice(users)
        if rnd.random() < 0.3:
            lines.append((t, f"web-01 sshd[{2100 + i}]: Invalid user {u} from 203.0.113.45 port {40000 + i}"))
        lines.append((t + timedelta(seconds=1),
                      f"web-01 sshd[{2100 + i}]: Failed password for {u} from 203.0.113.45 port {40000 + i} ssh2"))
    lines.append((ts(16, 10), "web-01 sshd[2190]: Accepted password for deploy from 203.0.113.45 port 40211 ssh2"))
    lines.append((ts(17, 2), "web-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"))
    lines.append((ts(17, 40), "web-01 sudo:   deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -e"))
    # normal admin activity
    for m in (3, 45, 95):
        lines.append((ts(m), f"web-01 sshd[{1800 + m}]: Accepted publickey for sysadmin from 10.0.1.10 port 52{m:03d} ssh2"))
    lines.append((ts(46), "web-01 sudo: sysadmin : TTY=pts/1 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/apt update"))
    # a user mistyping a password twice
    for k in range(2):
        lines.append((ts(70, k * 20), f"db-01 sshd[30{k}]: Failed password for priya from 10.0.1.22 port 51000 ssh2"))
    lines.append((ts(71), "db-01 sshd[303]: Accepted password for priya from 10.0.1.22 port 51001 ssh2"))
    lines.sort()
    return [f"{t:%b %d %H:%M:%S} {msg}" for t, msg in lines]


def suricata():
    recs = []

    def alert(t, src, dst, dport, sig, cat, sev, sid):
        recs.append({"timestamp": iso(t), "event_type": "alert", "src_ip": src, "src_port": rnd.randint(30000, 60000),
                     "dest_ip": dst, "dest_port": dport, "proto": "TCP", "in_iface": "eth1",
                     "alert": {"action": "allowed", "signature_id": sid, "signature": sig,
                               "category": cat, "severity": sev}})

    # 2. scan then web attacks
    for i, port in enumerate([21, 22, 25, 80, 443, 3306, 8080]):
        alert(ts(30, i * 3), "198.51.100.23", "10.0.0.5", port,
              "ET SCAN Possible Nmap SYN scan", "Attempted Information Leak", 3, 2009582)
    for i, sig in enumerate(["ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
                             "ET WEB_SERVER Possible SQL Injection Attempt OR 1=1",
                             "ET WEB_SERVER Directory Traversal Attempt ../../etc/passwd"]):
        alert(ts(34, i * 25), "198.51.100.23", "10.0.0.5", 443, sig, "Web Application Attack", 1, 2006446 + i)
    # 3. HR laptop beaconing
    for i in range(6):
        alert(ts(50 + i * 5), "10.0.2.15", "192.0.2.80", 443,
              "ET MALWARE Possible C2 beacon callback over TLS", "A Network Trojan was Detected", 1, 2027000)
    # noise
    for i in range(5):
        alert(ts(rnd.randint(0, 110)), f"10.0.1.{rnd.randint(30, 90)}", "10.0.0.53", 53,
              "ET POLICY DNS query to .onion proxy domain", "Potential Corporate Privacy Violation", 3, 2014939)
    # a non-alert event that must be ignored
    recs.append({"timestamp": iso(ts(1)), "event_type": "flow", "src_ip": "10.0.1.5", "dest_ip": "10.0.0.5"})
    recs.sort(key=lambda r: r["timestamp"])
    return recs


def wazuh():
    recs = []

    def alert(t, level, desc, agent, groups, data=None, mitre=None):
        rule = {"level": level, "description": desc, "id": str(rnd.randint(5000, 99999)), "groups": groups}
        if mitre:
            rule["mitre"] = {"id": [mitre[0]], "tactic": [mitre[1]]}
        recs.append({"timestamp": iso(t), "rule": rule, "agent": {"id": "00" + str(rnd.randint(1, 9)), "name": agent},
                     "data": data or {}})

    alert(ts(13), 10, "sshd: brute force trying to get access to the system. Non existent user.", "web-01",
          ["syslog", "sshd", "authentication_failures"], {"srcip": "203.0.113.45"}, ("T1110", "Credential Access"))
    alert(ts(16, 12), 3, "sshd: authentication success.", "web-01",
          ["syslog", "sshd", "authentication_success"], {"srcip": "203.0.113.45", "dstuser": "deploy"},
          ("T1078", "Initial Access"))
    alert(ts(17, 41), 8, "Crontab modified by non-admin user", "web-01", ["syscheck", "persistence"],
          {"dstuser": "deploy"}, ("T1053.003", "Persistence"))
    alert(ts(52), 12, "Suspicious outbound connection from process not normally using network", "laptop-hr-07",
          ["sysmon", "network"], {"srcip": "10.0.2.15", "dstip": "192.0.2.80"}, ("T1071", "Command and Control"))
    # noise
    for i in range(12):
        alert(ts(rnd.randint(0, 115)), rnd.choice([3, 3, 4, 5]),
              rnd.choice(["Integrity checksum changed.", "Windows Logon Success", "Service startup type was changed",
                          "Listened ports status (netstat) changed"]),
              rnd.choice(["web-01", "db-01", "dc-01", "laptop-fin-02"]), ["ossec"])
    recs.sort(key=lambda r: r["timestamp"])
    return recs


def main():
    with open(os.path.join(OUT, "auth.log"), "w") as fh:
        fh.write("\n".join(auth_log()) + "\n")
    with open(os.path.join(OUT, "suricata_eve.json"), "w") as fh:
        fh.write("\n".join(json.dumps(r) for r in suricata()) + "\n")
    with open(os.path.join(OUT, "wazuh_alerts.json"), "w") as fh:
        fh.write("\n".join(json.dumps(r) for r in wazuh()) + "\n")
    print("Wrote auth.log, suricata_eve.json, wazuh_alerts.json")


if __name__ == "__main__":
    main()
