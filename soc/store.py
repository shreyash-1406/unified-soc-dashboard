"""SQLite storage for alerts and analyst decisions on incidents."""

import json
import sqlite3

from .models import Alert, parse_time

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE,
    ts TEXT, source TEXT, severity TEXT, title TEXT,
    src_ip TEXT, dest_ip TEXT, host TEXT, user TEXT, category TEXT,
    technique TEXT, tactic TEXT, raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS incident_state (
    id TEXT PRIMARY KEY,
    status TEXT DEFAULT 'new',
    note TEXT DEFAULT '',
    ai_summary TEXT DEFAULT '',
    updated TEXT
);
"""

STATUSES = ["new", "investigating", "closed", "false_positive"]


class Store:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    def add_alerts(self, alerts):
        """Insert alerts; exact duplicates (same fingerprint) are ignored. Returns rows added."""
        before = self.count()
        self.conn.executemany(
            "INSERT OR IGNORE INTO alerts (fingerprint, ts, source, severity, title, src_ip, dest_ip, host, "
            "user, category, technique, tactic, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(a.fingerprint, a.timestamp.isoformat(), a.source, a.severity, a.title, a.src_ip, a.dest_ip,
              a.host, a.user, a.category, a.mitre_technique, a.mitre_tactic, json.dumps(a.raw)[:20000])
             for a in alerts])
        self.conn.commit()
        return self.count() - before

    def count(self):
        return self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def all_alerts(self):
        rows = self.conn.execute("SELECT * FROM alerts ORDER BY ts, id").fetchall()
        out = []
        for r in rows:
            a = Alert(timestamp=parse_time(r["ts"]), source=r["source"], title=r["title"],
                      severity=r["severity"], src_ip=r["src_ip"], dest_ip=r["dest_ip"], host=r["host"],
                      user=r["user"], category=r["category"], mitre_technique=r["technique"],
                      mitre_tactic=r["tactic"], raw=json.loads(r["raw"] or "{}"))
            a.db_id = r["id"]
            out.append(a)
        return out

    def state(self, incident_id):
        r = self.conn.execute("SELECT * FROM incident_state WHERE id = ?", (incident_id,)).fetchone()
        return dict(r) if r else {"id": incident_id, "status": "new", "note": "", "ai_summary": ""}

    def states(self):
        return {r["id"]: dict(r) for r in self.conn.execute("SELECT * FROM incident_state")}

    def update_state(self, incident_id, **fields):
        current = self.state(incident_id)
        current.update({k: v for k, v in fields.items() if v is not None})
        if current["status"] not in STATUSES:
            current["status"] = "new"
        self.conn.execute(
            "INSERT INTO incident_state (id, status, note, ai_summary, updated) VALUES (?,?,?,?,datetime('now')) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, note=excluded.note, "
            "ai_summary=excluded.ai_summary, updated=excluded.updated",
            (incident_id, current["status"], current["note"][:5000], current["ai_summary"][:10000]))
        self.conn.commit()

    def reset(self):
        self.conn.executescript("DELETE FROM alerts; DELETE FROM incident_state;")
        self.conn.commit()
