"""
Flask web app.

    GET  /                      dashboard: KPIs, timeline, sources, ATT&CK tactics, incident queue
    GET  /alerts                all alerts with filters
    GET  /incidents/<id>        incident detail, analyst status/notes, AI triage
    POST /incidents/<id>        update status / note
    POST /incidents/<id>/triage ask the AI model for a triage note
    GET  /ingest                upload a log file
    POST /ingest                parse and store a log file
    POST /demo                  load the bundled sample logs
    POST /reset                 delete everything
    POST /api/ingest            raw log lines in the body (?format=auto|wazuh|suricata|linux_auth|generic)
    GET  /api/incidents         incidents as JSON
"""

import os
from collections import Counter

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, url_for

from . import ai
from .correlate import build_incidents, dedupe, score_alerts, template_summary
from .parsers import parse_file, parse_lines
from .store import STATUSES, Store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = [os.path.join(ROOT, "sample_data", f) for f in ("auth.log", "suricata_eve.json", "wazuh_alerts.json")]
FORMATS = ["auto", "wazuh", "suricata", "linux_auth", "generic"]


def create_app(db_path=None, use_ai=None, critical_hosts=None):
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", os.urandom(16).hex())
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
    app.config["DB_PATH"] = db_path or os.getenv("SOC_DB", "soc.db")
    app.config["USE_AI"] = ai.enabled() if use_ai is None else use_ai
    app.config["CRITICAL_HOSTS"] = critical_hosts if critical_hosts is not None else \
        [h.strip() for h in os.getenv("CRITICAL_HOSTS", "web-01,db-01,dc-01").split(",") if h.strip()]

    def store():
        if "store" not in g:
            g.store = Store(app.config["DB_PATH"])
        return g.store

    @app.teardown_appcontext
    def _close(_e):
        s = g.pop("store", None)
        if s:
            s.close()

    def analyse():
        """Load alerts, score, correlate, merge analyst state. Cached per request."""
        if "analysis" in g:
            return g.analysis
        alerts = store().all_alerts()
        score_alerts(alerts, app.config["CRITICAL_HOSTS"])
        incidents = build_incidents(alerts)
        states = store().states()
        for inc in incidents:
            st = states.get(inc.id, {})
            inc.status = st.get("status", "new")
            inc.note = st.get("note", "")
            if st.get("ai_summary"):
                inc.summary, inc.summary_source = st["ai_summary"], "ai"
            else:
                inc.summary = template_summary(inc)
        g.analysis = (alerts, incidents)
        return g.analysis

    def ingest(alerts):
        alerts, _ = dedupe(alerts)
        return store().add_alerts(alerts)

    # ---------------- dashboard ----------------
    @app.get("/")
    def dashboard():
        alerts, incidents = analyse()
        open_inc = [i for i in incidents if i.status in ("new", "investigating")]
        by_sev = Counter(a.severity for a in alerts)
        by_source = Counter(a.source for a in alerts).most_common()
        by_tactic = Counter(a.mitre_tactic for a in alerts if a.mitre_tactic).most_common(8)

        # timeline: alerts per 10-minute bucket
        buckets = Counter()
        for a in alerts:
            buckets[a.timestamp.replace(minute=a.timestamp.minute // 10 * 10, second=0, microsecond=0)] += 1
        timeline = sorted(buckets.items())[-48:]
        peak = max([c for _, c in timeline] or [1])

        return render_template("dashboard.html", alerts=alerts, incidents=incidents, open_inc=open_inc,
                               by_sev=by_sev, by_source=by_source, by_tactic=by_tactic,
                               timeline=timeline, peak=peak, total=len(alerts),
                               critical_hosts=app.config["CRITICAL_HOSTS"])

    @app.get("/alerts")
    def alerts_view():
        alerts, _ = analyse()
        sev, src, q = request.args.get("severity", ""), request.args.get("source", ""), request.args.get("q", "").lower()
        rows = [a for a in alerts
                if (not sev or a.severity == sev) and (not src or a.source == src)
                and (not q or q in f"{a.title} {a.src_ip} {a.host} {a.user}".lower())]
        rows.sort(key=lambda a: (-a.risk_score, a.timestamp))
        sources = sorted({a.source for a in alerts})
        return render_template("alerts.html", rows=rows[:500], total=len(rows), sources=sources,
                               sev=sev, src=src, q=request.args.get("q", ""))

    def find_incident(iid):
        alerts, incidents = analyse()
        inc = next((i for i in incidents if i.id == iid), None)
        if not inc:
            abort(404)
        return inc, [alerts[k] for k in inc.alert_ids]

    @app.get("/incidents/<iid>")
    def incident(iid):
        inc, inc_alerts = find_incident(iid)
        return render_template("incident.html", inc=inc, alerts=inc_alerts, statuses=STATUSES,
                               ai_on=app.config["USE_AI"])

    @app.post("/incidents/<iid>")
    def update_incident(iid):
        find_incident(iid)
        store().update_state(iid, status=request.form.get("status"), note=request.form.get("note"))
        flash("Incident updated.")
        return redirect(url_for("incident", iid=iid))

    @app.post("/incidents/<iid>/triage")
    def triage(iid):
        inc, inc_alerts = find_incident(iid)
        text = ai.triage(vars(inc), [a.to_dict() for a in inc_alerts]) if app.config["USE_AI"] else None
        if text:
            store().update_state(iid, ai_summary=text)
            flash("AI triage note added.")
        else:
            flash("AI model not reachable; showing the rule-based summary.")
        return redirect(url_for("incident", iid=iid))

    # ---------------- ingestion ----------------
    @app.get("/ingest")
    def ingest_form():
        return render_template("ingest.html", formats=FORMATS)

    @app.post("/ingest")
    def ingest_upload():
        f = request.files.get("file")
        fmt = request.form.get("format", "auto")
        if not f or not f.filename:
            flash("Choose a log file to upload.")
            return redirect(url_for("ingest_form"))
        if fmt not in FORMATS:
            fmt = "auto"
        lines = f.read().decode("utf-8", errors="replace").splitlines()
        alerts, stats = parse_lines(lines, fmt)
        added = ingest(alerts)
        flash(f"{os.path.basename(f.filename)}: detected {stats['format']}, parsed {stats['parsed']}, "
              f"skipped {stats['skipped']}, {added} new alerts stored.")
        return redirect(url_for("dashboard"))

    @app.post("/demo")
    def demo():
        added = 0
        for path in SAMPLES:
            alerts, _ = parse_file(path)
            added += ingest(alerts)
        flash(f"Loaded sample data: {added} new alerts.")
        return redirect(url_for("dashboard"))

    @app.post("/reset")
    def reset():
        store().reset()
        flash("All alerts and incident notes deleted.")
        return redirect(url_for("dashboard"))

    # ---------------- API ----------------
    @app.post("/api/ingest")
    def api_ingest():
        fmt = request.args.get("format", "auto")
        if fmt not in FORMATS:
            return jsonify(error=f"format must be one of {FORMATS}"), 400
        alerts, stats = parse_lines(request.get_data(as_text=True).splitlines(), fmt)
        stats["stored"] = ingest(alerts)
        return jsonify(stats)

    @app.get("/api/incidents")
    def api_incidents():
        _, incidents = analyse()
        return jsonify([{k: v for k, v in vars(i).items() if k != "alert_ids"} | {"alerts": len(i.alert_ids)}
                        for i in incidents])

    return app
