"""
Optional AI triage.

For each incident, a local LLM (Ollama by default) writes a short analyst
note: what probably happened, how confident it is, and the next steps.
Detection, scoring and correlation stay rule-based, so the AI never decides
whether something is an incident, it only helps the analyst read it faster.

    USE_AI=0          disable
    LLM_BASE_URL      default http://localhost:11434/v1
    LLM_MODEL         default llama3.1:8b
"""

import json
import os

import requests

SYSTEM = ("You are a senior SOC analyst. Write concise, factual triage notes. "
          "Only use the evidence given. If the evidence is weak, say so.")

PROMPT = """Incident {id}: {title}
Severity: {severity}, risk {risk}/100
Entity: {entity}
Time: {first} to {last}
Sources: {sources}; hosts: {hosts}; users: {users}
MITRE ATT&CK: {techniques} ({tactics})
Correlation findings: {patterns}
Sample alerts (up to 8):
{samples}

Write a triage note in 3 short parts, plain text, no markdown headings:
1) What most likely happened (2 sentences).
2) Confidence (low/medium/high) and why (1 sentence).
3) Next steps for the analyst (3 short imperative items separated by semicolons)."""


def enabled():
    return os.getenv("USE_AI", "1") != "0"


def triage(incident, alerts, timeout=60):
    if not enabled():
        return None
    samples = "\n".join(f"- {a['timestamp'][11:19]} [{a['source']}] {a['severity']}: {a['title']}"
                        f"{' src=' + a['src_ip'] if a.get('src_ip') else ''}"
                        f"{' user=' + a['user'] if a.get('user') else ''}" for a in alerts[:8])
    prompt = PROMPT.format(
        id=incident["id"], title=incident["title"], severity=incident["severity"], risk=incident["risk"],
        entity=incident["entity"], first=incident["first_seen"], last=incident["last_seen"],
        sources=", ".join(incident["sources"]), hosts=", ".join(incident["hosts"]) or "-",
        users=", ".join(incident["users"]) or "-",
        techniques=", ".join(incident["techniques"]) or "-", tactics=", ".join(incident["tactics"]) or "-",
        patterns="; ".join(p["detail"] for p in incident["patterns"]) or "none", samples=samples)
    base = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1").rstrip("/")
    try:
        r = requests.post(f"{base}/chat/completions",
                          headers={"Authorization": f"Bearer {os.getenv('LLM_API_KEY', 'ollama')}"},
                          json={"model": os.getenv("LLM_MODEL", "llama3.1:8b"), "temperature": 0.2,
                                "messages": [{"role": "system", "content": SYSTEM},
                                             {"role": "user", "content": prompt}]},
                          timeout=timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip() or None
    except (requests.RequestException, KeyError, ValueError, IndexError, json.JSONDecodeError):
        return None
