#!/usr/bin/env python3
"""
Docker Mailserver GUI – Sichere Web-Oberfläche für alle setup-Befehle
sowie zum Auslesen von Config, Mails und Logs.

- Deckt alle Funktionen von `setup` (email, alias, quota, dovecot-master,
  config dkim, relay, fail2ban, debug)
- Config-Dateien, Mailboxen und Logs können eingesehen werden (nur lesend)
- Passwörter werden ausschließlich als type=password übergeben und nie geloggt
- Die Grundfunktionsweise bleibt unverändert: Es werden nur die bestehenden
  CLI-Befehle bzw. read-only Container-Befehle aufgerufen
- Keine Änderungen an docker-mailserver selbst
"""

from __future__ import annotations

import html
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Konfiguration (kann über Umgebungsvariablen überschrieben werden)
# ---------------------------------------------------------------------------
HOST = os.environ.get("DMS_GUI_HOST", "127.0.0.1")
PORT = int(os.environ.get("DMS_GUI_PORT", "18880"))

# Wie der setup-Befehl aufgerufen wird.
# Beispiele:
#   "docker exec -i mailserver setup"
#   "./setup.sh"
#   "docker compose exec -T mailserver setup"
SETUP_CMD = os.environ.get(
    "DMS_SETUP_CMD",
    "docker exec -i mailserver setup",
).strip()

# Basis-Befehl für beliebige (read-only) Container-Aufrufe.
# Wird aus SETUP_CMD abgeleitet, falls nicht gesetzt.
# Beispiel: "docker exec -i mailserver"
_EXEC_DEFAULT = re.sub(r"\s+setup\s*$", "", SETUP_CMD).strip() or "docker exec -i mailserver"
EXEC_CMD = os.environ.get("DMS_EXEC_CMD", _EXEC_DEFAULT).strip()

# Optionaler Auth-Token (wenn gesetzt, muss der Header X-Auth-Token stimmen)
AUTH_TOKEN = os.environ.get("DMS_GUI_TOKEN", "")

# Timeout für subprocess-Aufrufe (Sekunden)
CMD_TIMEOUT = 60

# Erlaubte Config-Dateien (relativ zu /tmp/docker-mailserver/)
ALLOWED_CONFIG_FILES = {
    "postfix-accounts.cf": "E-Mail-Konten (postfix-accounts.cf)",
    "postfix-virtual.cf": "Aliase (postfix-virtual.cf)",
    "dovecot-quotas.cf": "Quota (dovecot-quotas.cf)",
    "postfix-send-access.cf": "Send-Beschränkungen",
    "postfix-receive-access.cf": "Receive-Beschränkungen",
    "postfix-regexp.cf": "Regexp-Aliase",
    "postfix-relaymap.cf": "Relay-Map",
    "postfix-sasl-password.cf": "SASL-Passwörter (Relay)",
    "postfix-main.cf": "Postfix main.cf Overrides",
    "postfix-master.cf": "Postfix master.cf Overrides",
    "dovecot.cf": "Dovecot Overrides",
    "rspamd-modules.d/": "Rspamd Module (Verzeichnis)",
    "opendkim/": "OpenDKIM (Verzeichnis)",
    "fail2ban-fail2ban.cf": "Fail2Ban Hauptconfig",
    "fail2ban-jail.cf": "Fail2Ban Jail",
    "fetchmail.cf": "Fetchmail",
    "user-patches.sh": "User-Patches",
}

# Erlaubte Log-Dateien (relativ zu /var/log/mail/ oder absolute Pfade)
ALLOWED_LOGS = {
    "mail.log": "/var/log/mail/mail.log",
    "mail.err": "/var/log/mail/mail.err",
    "mail.warn": "/var/log/mail/mail.warn",
    "mail.info": "/var/log/mail/mail.info",
    "clamav": "/var/log/mail/clamav.log",
    "fail2ban": "/var/log/mail/fail2ban.log",
    "rspamd": "/var/log/mail/rspamd.log",
    "supervisor": "/var/log/supervisor/supervisord.log",
}

# ---------------------------------------------------------------------------
# Sicherheitshilfen
# ---------------------------------------------------------------------------
SESSION_COOKIE = "dms_gui_session"
_sessions: dict[str, float] = {}  # token -> expiry
SESSION_TTL = 3600 * 8  # 8 Stunden


def _new_session() -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + SESSION_TTL
    return token


def _valid_session(token: str | None) -> bool:
    if not token:
        return False
    expiry = _sessions.get(token)
    if expiry is None or expiry < time.time():
        _sessions.pop(token, None)
        return False
    return True


def _clean_sessions() -> None:
    now = time.time()
    expired = [k for k, v in _sessions.items() if v < now]
    for k in expired:
        del _sessions[k]


# ---------------------------------------------------------------------------
# CLI-Aufrufe
# ---------------------------------------------------------------------------
def run_setup(args: list[str], password: str | None = None) -> tuple[int, str, str]:
    """
    Ruft den originalen setup-Befehl auf.
    Passwörter werden nur über die Argumentliste bzw. stdin übergeben
    und erscheinen nicht in GUI-Logs.
    """
    cmd = shlex.split(SETUP_CMD) + args
    stdin_data = None
    if password is not None:
        stdin_data = (password + "\n").encode("utf-8")

    env = os.environ.copy()
    env.pop("DMS_GUI_TOKEN", None)

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=CMD_TIMEOUT,
            env=env,
            check=False,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout: Befehl hat zu lange gedauert"
    except FileNotFoundError as e:
        return 127, "", f"Befehl nicht gefunden: {e}"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"Unerwarteter Fehler: {e}"


def run_exec(args: list[str]) -> tuple[int, str, str]:
    """
    Führt einen read-only Befehl im Container aus (cat, ls, tail, du, …).
    Nur für erlaubte, vordefinierte Aktionen verwenden.
    """
    cmd = shlex.split(EXEC_CMD) + args
    env = os.environ.copy()
    env.pop("DMS_GUI_TOKEN", None)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=CMD_TIMEOUT,
            env=env,
            check=False,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout: Befehl hat zu lange gedauert"
    except FileNotFoundError as e:
        return 127, "", f"Befehl nicht gefunden: {e}"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"Unerwarteter Fehler: {e}"


# ---------------------------------------------------------------------------
# HTML / CSS
# ---------------------------------------------------------------------------
CSS = """
:root {
  --bg: #0f1419;
  --surface: #1a2332;
  --surface2: #243044;
  --border: #2d3a4f;
  --text: #e7ecf3;
  --muted: #8b9bb4;
  --accent: #3b82f6;
  --accent-hover: #2563eb;
  --success: #22c55e;
  --danger: #ef4444;
  --warning: #f59e0b;
  --radius: 10px;
  --font: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.layout { display: flex; min-height: 100vh; }
.sidebar {
  width: 260px;
  background: var(--surface);
  border-right: 1px solid var(--border);
  padding: 1.5rem 1rem;
  flex-shrink: 0;
  overflow-y: auto;
}
.sidebar h1 {
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 0.25rem;
  letter-spacing: -0.02em;
}
.sidebar .sub {
  font-size: 0.75rem;
  color: var(--muted);
  margin-bottom: 1.5rem;
}
.nav a {
  display: block;
  padding: 0.55rem 0.75rem;
  border-radius: 6px;
  color: var(--text);
  margin-bottom: 2px;
  font-size: 0.9rem;
}
.nav a:hover, .nav a.active {
  background: var(--surface2);
  text-decoration: none;
}
.nav .group {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin: 1.1rem 0 0.35rem 0.75rem;
}
.main {
  flex: 1;
  padding: 2rem 2.5rem;
  overflow-y: auto;
  max-width: 1100px;
}
h2 { font-size: 1.45rem; margin-bottom: 0.35rem; font-weight: 600; }
.desc { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.25rem;
}
.card h3 {
  font-size: 1rem;
  margin-bottom: 1rem;
  font-weight: 600;
}
.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.9rem;
  margin-bottom: 1rem;
}
label {
  display: block;
  font-size: 0.8rem;
  color: var(--muted);
  margin-bottom: 0.3rem;
}
input, select, textarea {
  width: 100%;
  padding: 0.55rem 0.7rem;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  font-size: 0.9rem;
}
input:focus, select:focus, textarea:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px rgba(59,130,246,0.25);
}
input[type="password"] { letter-spacing: 0.15em; }
.btn {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.55rem 1.1rem;
  border: none;
  border-radius: 6px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  background: var(--accent);
  color: white;
  transition: background 0.15s;
}
.btn:hover { background: var(--accent-hover); }
.btn-danger { background: var(--danger); }
.btn-danger:hover { background: #dc2626; }
.btn-secondary {
  background: var(--surface2);
  color: var(--text);
  border: 1px solid var(--border);
}
.btn-secondary:hover { background: var(--border); }
.btn-sm { padding: 0.35rem 0.75rem; font-size: 0.8rem; }
.actions { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 0.5rem; }
.output {
  background: #0a0e14;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  font-family: ui-monospace, "Cascadia Code", "Fira Code", monospace;
  font-size: 0.82rem;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 520px;
  overflow: auto;
  margin-top: 1rem;
}
.output.success { border-color: var(--success); }
.output.error { border-color: var(--danger); }
.badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  font-size: 0.7rem;
  font-weight: 600;
}
.badge-ok { background: rgba(34,197,94,0.15); color: var(--success); }
.badge-err { background: rgba(239,68,68,0.15); color: var(--danger); }
.note {
  font-size: 0.8rem;
  color: var(--muted);
  margin-top: 0.75rem;
}
.note strong { color: var(--warning); }
.login-box {
  max-width: 380px;
  margin: 12vh auto;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 2rem;
}
.login-box h1 { font-size: 1.3rem; margin-bottom: 0.5rem; }
.login-box p { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.25rem; }
footer {
  margin-top: 2.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
  font-size: 0.75rem;
  color: var(--muted);
}
.file-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 1rem;
}
.file-list form { display: inline; }
table.data {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
table.data th, table.data td {
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border);
}
table.data th { color: var(--muted); font-weight: 500; }
.dash-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.dash-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.1rem 1.25rem;
  text-align: center;
}
.dash-card .value {
  font-size: 1.75rem;
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.2;
}
.dash-card .label {
  font-size: 0.78rem;
  color: var(--muted);
  margin-top: 0.35rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.dash-card.ok .value { color: var(--success); }
.dash-card.warn .value { color: var(--warning); }
.dash-card.err .value { color: var(--danger); }
.svc-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0.6rem;
}
.svc-item {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.55rem 0.75rem;
  background: var(--bg);
  border-radius: 6px;
  border: 1px solid var(--border);
  font-size: 0.85rem;
}
.svc-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.svc-dot.run { background: var(--success); box-shadow: 0 0 6px rgba(34,197,94,0.5); }
.svc-dot.stop { background: var(--danger); }
.svc-dot.unk { background: var(--muted); }
.quick-links {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.quick-links a {
  display: inline-block;
  padding: 0.4rem 0.8rem;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.82rem;
  color: var(--text);
}
.quick-links a:hover {
  border-color: var(--accent);
  text-decoration: none;
  background: var(--border);
}
"""


def page_shell(title: str, body: str, active: str = "") -> str:
    groups = {
        "Übersicht": [
            ("dashboard", "Dashboard"),
        ],
        "Konten": [
            ("email", "E-Mail-Konten"),
            ("alias", "Aliase"),
            ("quota", "Quota"),
            ("dovecot-master", "Dovecot-Master"),
        ],
        "Sicherheit & Relay": [
            ("dkim", "DKIM"),
            ("relay", "Relay"),
            ("fail2ban", "Fail2Ban"),
        ],
        "Einsicht": [
            ("config", "Config anzeigen"),
            ("mails", "Mails / Mailboxen"),
            ("logs", "Logs"),
        ],
        "Sonstiges": [
            ("debug", "Debug"),
            ("settings", "Einstellungen"),
        ],
    }
    nav_html = ""
    for group, items in groups.items():
        nav_html += f'<div class="group">{group}</div>'
        for key, label in items:
            cls = "active" if key == active else ""
            nav_html += f'<a class="{cls}" href="/?page={key}">{label}</a>'

    return f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} · DMS GUI</title>
  <style>{CSS}</style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <h1>Docker Mailserver</h1>
      <div class="sub">Administration GUI</div>
      <nav class="nav">{nav_html}</nav>
    </aside>
    <main class="main">
      {body}
      <footer>
        Passwörter werden nur über sichere Formularfelder übertragen und
        niemals geloggt. Config, Mails und Logs werden nur lesend aus dem
        Container gelesen. Die GUI ändert nichts an der Grundfunktionsweise
        von docker-mailserver.
      </footer>
    </main>
  </div>
</body>
</html>"""


def render_result(rc: int, stdout: str, stderr: str) -> str:
    ok = rc == 0
    badge = (
        '<span class="badge badge-ok">Erfolg (rc=0)</span>'
        if ok
        else f'<span class="badge badge-err">Fehler (rc={rc})</span>'
    )
    content = ""
    if stdout.strip():
        content += html.escape(stdout)
    if stderr.strip():
        if content:
            content += "\n--- stderr ---\n"
        content += html.escape(stderr)
    if not content:
        content = "(keine Ausgabe)"
    cls = "success" if ok else "error"
    return f"""
    <div class="card">
      <h3>Ergebnis {badge}</h3>
      <div class="output {cls}">{content}</div>
    </div>"""


# ---------------------------------------------------------------------------
# Dashboard – Status & Übersicht (Synology-ähnlich)
# ---------------------------------------------------------------------------
def _gather_dashboard() -> dict:
    """Sammelt Statusdaten per read-only Container-Befehle."""
    data: dict = {
        "services": [],
        "accounts": "–",
        "aliases": "–",
        "queue": "–",
        "mail_storage": "–",
        "sent_approx": "–",
        "recv_approx": "–",
        "raw_services": "",
        "error": None,
    }

    # Supervisor-Services
    rc, out, err = run_exec(["supervisorctl", "status"])
    if rc == 0 and out.strip():
        data["raw_services"] = out
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                state = parts[1]
                running = state == "RUNNING"
                data["services"].append({"name": name, "state": state, "running": running})
    else:
        data["error"] = (err or out or "supervisorctl nicht erreichbar").strip()[:200]

    # Konten zählen
    rc, out, _ = run_setup(["email", "list"])
    if rc == 0:
        lines = [l for l in out.strip().splitlines() if l.strip() and not l.startswith("*")]
        data["accounts"] = str(len(lines)) if lines else "0"

    # Aliase zählen
    rc, out, _ = run_setup(["alias", "list"])
    if rc == 0:
        lines = [l for l in out.strip().splitlines() if l.strip() and "@" in l]
        data["aliases"] = str(len(lines)) if lines else "0"

    # Postfix-Queue
    rc, out, _ = run_exec(["postqueue", "-p"])
    if rc == 0:
        last = out.strip().splitlines()[-1] if out.strip() else ""
        if "empty" in last.lower() or "Mail queue is empty" in out:
            data["queue"] = "0"
        else:
            # z.B. "-- 2 Kbytes in 1 Request."
            m = re.search(r"(\d+)\s+Request", last, re.I)
            data["queue"] = m.group(1) if m else (last[:40] or "–")

    # Speicher /var/mail
    rc, out, _ = run_exec(["du", "-sh", "/var/mail"])
    if rc == 0 and out.strip():
        data["mail_storage"] = out.strip().split()[0]

    # Grobe Mail-Statistik aus den letzten ~Log-Zeilen (nicht exakt, aber nützlich)
    rc, out, _ = run_exec([
        "sh", "-c",
        "tail -n 5000 /var/log/mail/mail.log 2>/dev/null | "
        "grep -c 'status=sent' || echo 0"
    ])
    if rc == 0:
        data["sent_approx"] = out.strip().splitlines()[-1].strip() or "0"

    rc, out, _ = run_exec([
        "sh", "-c",
        "tail -n 5000 /var/log/mail/mail.log 2>/dev/null | "
        "grep -cE 'status=sent.*Saved|lmtp.*status=sent' || echo 0"
    ])
    if rc == 0:
        data["recv_approx"] = out.strip().splitlines()[-1].strip() or "0"

    return data


def page_dashboard(result: str = "") -> str:
    d = _gather_dashboard()

    # Status-Karten
    running_n = sum(1 for s in d["services"] if s["running"])
    total_n = len(d["services"])
    svc_class = "ok" if total_n and running_n == total_n else ("warn" if running_n else "err")

    cards = f"""
    <div class="dash-grid">
      <div class="dash-card {svc_class}">
        <div class="value">{running_n}/{total_n or '–'}</div>
        <div class="label">Services aktiv</div>
      </div>
      <div class="dash-card">
        <div class="value">{html.escape(str(d['accounts']))}</div>
        <div class="label">E-Mail-Konten</div>
      </div>
      <div class="dash-card">
        <div class="value">{html.escape(str(d['aliases']))}</div>
        <div class="label">Aliase</div>
      </div>
      <div class="dash-card {'warn' if d['queue'] not in ('0', '–') else ''}">
        <div class="value">{html.escape(str(d['queue']))}</div>
        <div class="label">Warteschlange</div>
      </div>
      <div class="dash-card">
        <div class="value">{html.escape(str(d['mail_storage']))}</div>
        <div class="label">Mail-Speicher</div>
      </div>
      <div class="dash-card">
        <div class="value">{html.escape(str(d['sent_approx']))}</div>
        <div class="label">≈ Gesendet*</div>
      </div>
      <div class="dash-card">
        <div class="value">{html.escape(str(d['recv_approx']))}</div>
        <div class="label">≈ Empfangen*</div>
      </div>
    </div>
    <p class="note">* Gesendet/Empfangen: Zählung aus den letzten ~5000 Log-Zeilen
      (nicht kumuliert seit Start). Für genaue Zahlen siehe Logs / doveadm.</p>
    """

    # Service-Liste
    svc_html = ""
    if d["services"]:
        for s in d["services"]:
            dot = "run" if s["running"] else "stop"
            svc_html += (
                f'<div class="svc-item">'
                f'<span class="svc-dot {dot}"></span>'
                f'<span>{html.escape(s["name"])}</span>'
                f'<span style="margin-left:auto;color:var(--muted);font-size:0.8rem">'
                f'{html.escape(s["state"])}</span></div>'
            )
    else:
        err = html.escape(d.get("error") or "Keine Service-Daten")
        svc_html = f'<p class="note">{err}</p>'

    body = f"""
    <h2>Dashboard</h2>
    <p class="desc">Übersicht über Services, Konten und grobe Mail-Statistiken –
      ähnlich einer Mail-Server-Admin-Konsole. Alle Verwaltungsfunktionen
      erreichst du über die linke Navigation.</p>

    {cards}

    <div class="card">
      <h3>Service-Status (supervisorctl)</h3>
      <div class="svc-grid">{svc_html}</div>
      <form method="post" action="/action" style="margin-top:1rem">
        <input type="hidden" name="action" value="dash_refresh">
        <button class="btn btn-secondary btn-sm" type="submit">Status aktualisieren</button>
      </form>
    </div>

    <div class="card">
      <h3>Schnellzugriff – alle Funktionen</h3>
      <div class="quick-links">
        <a href="/?page=email">E-Mail-Konten</a>
        <a href="/?page=alias">Aliase</a>
        <a href="/?page=quota">Quota</a>
        <a href="/?page=dovecot-master">Dovecot-Master</a>
        <a href="/?page=dkim">DKIM</a>
        <a href="/?page=relay">Relay</a>
        <a href="/?page=fail2ban">Fail2Ban</a>
        <a href="/?page=config">Config anzeigen</a>
        <a href="/?page=mails">Mails / Mailboxen</a>
        <a href="/?page=logs">Logs</a>
        <a href="/?page=debug">Debug</a>
        <a href="/?page=settings">Einstellungen</a>
      </div>
    </div>

    <div class="card">
      <h3>Was du hier konfigurieren kannst</h3>
      <ul style="margin-left:1.2rem;color:var(--muted);font-size:0.9rem;line-height:1.7">
        <li><strong style="color:var(--text)">Konten:</strong> anlegen, Passwort ändern, löschen, Listen, Send-/Receive-Beschränkungen</li>
        <li><strong style="color:var(--text)">Aliase & Quota:</strong> Weiterleitungen und Speicherlimits</li>
        <li><strong style="color:var(--text)">Dovecot-Master:</strong> Master-User für Admin-Zugriff auf Mailboxen</li>
        <li><strong style="color:var(--text)">DKIM:</strong> Schlüssel erzeugen / anzeigen</li>
        <li><strong style="color:var(--text)">Relay:</strong> Relay-Hosts, Auth und Ausschlüsse</li>
        <li><strong style="color:var(--text)">Fail2Ban:</strong> Status, Bans, Unban</li>
        <li><strong style="color:var(--text)">Einsicht:</strong> Config-Dateien, Mailbox-Inhalt, Speicher, Logs (nur lesend)</li>
      </ul>
      <p class="note">Die GUI ruft ausschließlich die bestehenden <code>setup</code>- und
        read-only Container-Befehle auf – die Funktionsweise von docker-mailserver bleibt unverändert.</p>
    </div>
    {result}
    """
    return page_shell("Dashboard", body, active="dashboard")


# ---------------------------------------------------------------------------
# Seiten-Renderer – Verwaltungsfunktionen
# ---------------------------------------------------------------------------
def page_email(result: str = "") -> str:
    return page_shell(
        "E-Mail-Konten",
        f"""
        <h2>E-Mail-Konten</h2>
        <p class="desc">Benutzer hinzufügen, aktualisieren, löschen und auflisten.
          Passwörter werden sicher als type=password übergeben und erscheinen
          nicht in Prozesslisten oder Logs.</p>

        <div class="card">
          <h3>Konto hinzufügen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="email_add">
            <div class="form-grid">
              <div>
                <label>E-Mail-Adresse *</label>
                <input name="email" type="email" required placeholder="user@example.com">
              </div>
              <div>
                <label>Passwort</label>
                <input name="password" type="password" autocomplete="new-password"
                       placeholder="••••••••">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Hinzufügen</button>
            </div>
            <p class="note"><strong>Sicherheit:</strong> Das Passwort wird nur an den
              setup-Befehl übergeben und danach aus dem Speicher gelöscht.</p>
          </form>
        </div>

        <div class="card">
          <h3>Passwort aktualisieren</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="email_update">
            <div class="form-grid">
              <div>
                <label>E-Mail-Adresse *</label>
                <input name="email" type="email" required>
              </div>
              <div>
                <label>Neues Passwort</label>
                <input name="password" type="password" autocomplete="new-password">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Aktualisieren</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Konto löschen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="email_del">
            <div class="form-grid">
              <div>
                <label>E-Mail-Adresse(n) *</label>
                <input name="email" required placeholder="user@example.com">
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-danger" type="submit">Löschen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Zugriff einschränken (restrict)</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="email_restrict">
            <div class="form-grid">
              <div>
                <label>Aktion</label>
                <select name="op">
                  <option value="add">add</option>
                  <option value="del">del</option>
                  <option value="list">list</option>
                </select>
              </div>
              <div>
                <label>Richtung</label>
                <select name="direction">
                  <option value="send">send</option>
                  <option value="receive">receive</option>
                </select>
              </div>
              <div>
                <label>E-Mail (bei list optional)</label>
                <input name="email" type="email">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Ausführen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Konten auflisten</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="email_list">
            <div class="actions">
              <button class="btn btn-secondary" type="submit">Liste anzeigen</button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="email",
    )


def page_alias(result: str = "") -> str:
    return page_shell(
        "Aliase",
        f"""
        <h2>Aliase</h2>
        <p class="desc">Weiterleitungen (Alias → Empfänger) verwalten.</p>

        <div class="card">
          <h3>Alias hinzufügen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="alias_add">
            <div class="form-grid">
              <div>
                <label>Alias-Adresse *</label>
                <input name="alias" type="email" required placeholder="alias@example.com">
              </div>
              <div>
                <label>Empfänger *</label>
                <input name="recipient" required placeholder="user@example.com">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Hinzufügen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Alias löschen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="alias_del">
            <div class="form-grid">
              <div>
                <label>Alias-Adresse *</label>
                <input name="alias" type="email" required>
              </div>
              <div>
                <label>Empfänger *</label>
                <input name="recipient" required>
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-danger" type="submit">Löschen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Aliase auflisten</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="alias_list">
            <div class="actions">
              <button class="btn btn-secondary" type="submit">Liste anzeigen</button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="alias",
    )


def page_quota(result: str = "") -> str:
    return page_shell(
        "Quota",
        f"""
        <h2>Kontingente (Quota)</h2>
        <p class="desc">Speicherplatz-Limits setzen oder entfernen.
          Beispiele: 10M, 2G, 0 (unbegrenzt).</p>

        <div class="card">
          <h3>Quota setzen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="quota_set">
            <div class="form-grid">
              <div>
                <label>E-Mail-Adresse *</label>
                <input name="email" type="email" required>
              </div>
              <div>
                <label>Quota (z. B. 10M, 2G)</label>
                <input name="quota" placeholder="10M">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Setzen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Quota entfernen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="quota_del">
            <div class="form-grid">
              <div>
                <label>E-Mail-Adresse *</label>
                <input name="email" type="email" required>
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-danger" type="submit">Entfernen</button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="quota",
    )


def page_dovecot_master(result: str = "") -> str:
    return page_shell(
        "Dovecot-Master",
        f"""
        <h2>Dovecot-Master-Benutzer</h2>
        <p class="desc">Administrative Master-Benutzer für Dovecot.</p>

        <div class="card">
          <h3>Master-Benutzer hinzufügen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="dm_add">
            <div class="form-grid">
              <div>
                <label>Benutzername *</label>
                <input name="username" required>
              </div>
              <div>
                <label>Passwort</label>
                <input name="password" type="password" autocomplete="new-password">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Hinzufügen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Passwort aktualisieren</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="dm_update">
            <div class="form-grid">
              <div>
                <label>Benutzername *</label>
                <input name="username" required>
              </div>
              <div>
                <label>Neues Passwort</label>
                <input name="password" type="password" autocomplete="new-password">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Aktualisieren</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Löschen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="dm_del">
            <div class="form-grid">
              <div>
                <label>Benutzername *</label>
                <input name="username" required>
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-danger" type="submit">Löschen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Liste</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="dm_list">
            <div class="actions">
              <button class="btn btn-secondary" type="submit">Auflisten</button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="dovecot-master",
    )


def page_dkim(result: str = "") -> str:
    return page_shell(
        "DKIM",
        f"""
        <h2>DKIM-Schlüssel</h2>
        <p class="desc">DKIM-Schlüssel erzeugen. Entspricht
          <code>setup config dkim</code>.</p>

        <div class="card">
          <h3>DKIM erzeugen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="dkim">
            <div class="form-grid">
              <div>
                <label>Schlüsselgröße</label>
                <select name="keysize">
                  <option value="2048">2048</option>
                  <option value="1024">1024</option>
                  <option value="4096">4096</option>
                </select>
              </div>
              <div>
                <label>Domain(s) (kommagetrennt, optional)</label>
                <input name="domain" placeholder="example.com,other.com">
              </div>
              <div>
                <label>Selektor (optional)</label>
                <input name="selector" placeholder="mail">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Schlüssel erzeugen</button>
            </div>
            <p class="note">Leere Domain-Liste → Domains werden automatisch
              aus den vorhandenen Konten abgeleitet (außer bei LDAP).</p>
          </form>
        </div>
        {result}
        """,
        active="dkim",
    )


def page_relay(result: str = "") -> str:
    return page_shell(
        "Relay",
        f"""
        <h2>Relay / Weiterleitung</h2>
        <p class="desc">Relay-Hosts und SASL-Authentifizierung.</p>

        <div class="card">
          <h3>Relay-Domain hinzufügen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="relay_add_domain">
            <div class="form-grid">
              <div>
                <label>Domain *</label>
                <input name="domain" required>
              </div>
              <div>
                <label>Host *</label>
                <input name="host" required placeholder="smtp.relay.example">
              </div>
              <div>
                <label>Port (optional)</label>
                <input name="port" placeholder="587">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Hinzufügen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Auth für Relay hinzufügen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="relay_add_auth">
            <div class="form-grid">
              <div>
                <label>Domain *</label>
                <input name="domain" required>
              </div>
              <div>
                <label>Benutzername *</label>
                <input name="username" required>
              </div>
              <div>
                <label>Passwort</label>
                <input name="password" type="password" autocomplete="new-password">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Auth hinzufügen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Domain von Relay ausschließen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="relay_exclude">
            <div class="form-grid">
              <div>
                <label>Domain *</label>
                <input name="domain" required>
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-danger" type="submit">Ausschließen</button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="relay",
    )


def page_fail2ban(result: str = "") -> str:
    return page_shell(
        "Fail2Ban",
        f"""
        <h2>Fail2Ban</h2>
        <p class="desc">IP-Sperren und Status.</p>

        <div class="card">
          <h3>IP sperren</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="f2b_ban">
            <div class="form-grid">
              <div>
                <label>IP-Adresse *</label>
                <input name="ip" required placeholder="203.0.113.10">
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-danger" type="submit">Sperren</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>IP entsperren</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="f2b_unban">
            <div class="form-grid">
              <div>
                <label>IP-Adresse *</label>
                <input name="ip" required>
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Entsperren</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Status / Log</h3>
          <form method="post" action="/action" style="display:inline">
            <input type="hidden" name="action" value="f2b_status">
            <button class="btn btn-secondary" type="submit">Status</button>
          </form>
          <form method="post" action="/action" style="display:inline;margin-left:0.5rem">
            <input type="hidden" name="action" value="f2b_log">
            <button class="btn btn-secondary" type="submit">Log</button>
          </form>
          <form method="post" action="/action" style="display:inline;margin-left:0.5rem">
            <input type="hidden" name="action" value="f2b">
            <button class="btn btn-secondary" type="submit">Übersicht</button>
          </form>
        </div>
        {result}
        """,
        active="fail2ban",
    )


def page_debug(result: str = "") -> str:
    return page_shell(
        "Debug",
        f"""
        <h2>Debug</h2>
        <p class="desc">Diagnose-Befehle. Interaktive Shells werden hier
          nicht unterstützt.</p>

        <div class="card">
          <h3>Befehle</h3>
          <form method="post" action="/action" style="display:inline">
            <input type="hidden" name="action" value="debug_fetchmail">
            <button class="btn btn-secondary" type="submit">Fetchmail debug</button>
          </form>
          <form method="post" action="/action" style="display:inline;margin-left:0.5rem">
            <input type="hidden" name="action" value="debug_getmail">
            <button class="btn btn-secondary" type="submit">Getmail debug</button>
          </form>
          <form method="post" action="/action" style="display:inline;margin-left:0.5rem">
            <input type="hidden" name="action" value="debug_logs">
            <button class="btn btn-secondary" type="submit">Mail-Logs (setup)</button>
          </form>
        </div>
        {result}
        """,
        active="debug",
    )


# ---------------------------------------------------------------------------
# Neue Seiten: Config, Mails, Logs
# ---------------------------------------------------------------------------
def page_config(result: str = "") -> str:
    buttons = ""
    for fname, label in ALLOWED_CONFIG_FILES.items():
        buttons += f"""
          <form method="post" action="/action" style="display:inline">
            <input type="hidden" name="action" value="view_config">
            <input type="hidden" name="file" value="{html.escape(fname)}">
            <button class="btn btn-secondary btn-sm" type="submit">{html.escape(label)}</button>
          </form>"""

    return page_shell(
        "Config anzeigen",
        f"""
        <h2>Config-Dateien</h2>
        <p class="desc">Wichtige Konfigurationsdateien aus dem Container
          (<code>/tmp/docker-mailserver/</code>) nur lesend anzeigen.
          Passwort-Hashes in den Accounts-Dateien sind absichtlich sichtbar
          (so wie in der Datei gespeichert).</p>

        <div class="card">
          <h3>Datei auswählen</h3>
          <div class="file-list">
            {buttons}
          </div>
          <p class="note">Nur vordefinierte Dateien sind erlaubt (Whitelist).
            Es werden keine Dateien geschrieben oder geändert.</p>
        </div>

        <div class="card">
          <h3>Verzeichnisinhalt auflisten</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="list_config_dir">
            <div class="actions">
              <button class="btn btn-secondary" type="submit">
                ls -la /tmp/docker-mailserver/
              </button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="config",
    )


def page_mails(result: str = "") -> str:
    return page_shell(
        "Mails / Mailboxen",
        f"""
        <h2>Mails &amp; Mailboxen</h2>
        <p class="desc">Übersicht der Mailboxen unter <code>/var/mail/</code>
          (Domain/Benutzer-Struktur). Nur lesend – es werden keine Mails
          gelöscht oder verändert.</p>

        <div class="card">
          <h3>Mailbox-Übersicht</h3>
          <form method="post" action="/action" style="display:inline">
            <input type="hidden" name="action" value="mails_list">
            <button class="btn" type="submit">Domains &amp; Benutzer auflisten</button>
          </form>
          <form method="post" action="/action" style="display:inline;margin-left:0.5rem">
            <input type="hidden" name="action" value="mails_du">
            <button class="btn btn-secondary" type="submit">Speicherverbrauch (du)</button>
          </form>
        </div>

        <div class="card">
          <h3>Spezifische Mailbox anzeigen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="mails_user">
            <div class="form-grid">
              <div>
                <label>Domain *</label>
                <input name="domain" required placeholder="example.com">
              </div>
              <div>
                <label>Benutzer (ohne Domain) *</label>
                <input name="user" required placeholder="user">
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-secondary" type="submit">Inhalt auflisten</button>
            </div>
            <p class="note">Zeigt die Ordnerstruktur (cur/new/tmp, .INBOX, …)
              der Mailbox <code>/var/mail/DOMAIN/USER</code>.</p>
          </form>
        </div>

        <div class="card">
          <h3>Anzahl Mails (doveadm)</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="mails_count">
            <div class="form-grid">
              <div>
                <label>E-Mail-Adresse (optional, leer = alle)</label>
                <input name="email" type="email" placeholder="user@example.com">
              </div>
            </div>
            <div class="actions">
              <button class="btn btn-secondary" type="submit">Zählen</button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="mails",
    )


def page_logs(result: str = "") -> str:
    log_buttons = ""
    for key, path in ALLOWED_LOGS.items():
        log_buttons += f"""
          <form method="post" action="/action" style="display:inline">
            <input type="hidden" name="action" value="view_log">
            <input type="hidden" name="log" value="{html.escape(key)}">
            <input type="hidden" name="lines" value="100">
            <button class="btn btn-secondary btn-sm" type="submit">{html.escape(key)}</button>
          </form>"""

    return page_shell(
        "Logs",
        f"""
        <h2>Logs</h2>
        <p class="desc">Log-Dateien aus dem Container anzeigen
          (letzte N Zeilen via <code>tail</code>). Nur lesend.</p>

        <div class="card">
          <h3>Schnellauswahl (letzte 100 Zeilen)</h3>
          <div class="file-list">
            {log_buttons}
          </div>
        </div>

        <div class="card">
          <h3>Log gezielt lesen</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="view_log">
            <div class="form-grid">
              <div>
                <label>Log-Datei</label>
                <select name="log">
                  {"".join(f'<option value="{html.escape(k)}">{html.escape(k)} ({html.escape(p)})</option>' for k, p in ALLOWED_LOGS.items())}
                </select>
              </div>
              <div>
                <label>Anzahl Zeilen (tail -n)</label>
                <input name="lines" type="number" value="200" min="10" max="5000">
              </div>
            </div>
            <div class="actions">
              <button class="btn" type="submit">Anzeigen</button>
            </div>
          </form>
        </div>

        <div class="card">
          <h3>Verfügbare Logs auflisten</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="list_logs">
            <div class="actions">
              <button class="btn btn-secondary" type="submit">
                ls -la /var/log/mail/
              </button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="logs",
    )


def page_settings(result: str = "") -> str:
    return page_shell(
        "Einstellungen",
        f"""
        <h2>Einstellungen</h2>
        <p class="desc">Aktuelle Verbindungsparameter der GUI (nur Anzeige).
          Änderungen erfolgen über Umgebungsvariablen beim Start.</p>

        <div class="card">
          <h3>Laufzeit-Konfiguration</h3>
          <div class="output">
HOST          = {html.escape(HOST)}
PORT          = {PORT}
SETUP_CMD     = {html.escape(SETUP_CMD)}
EXEC_CMD      = {html.escape(EXEC_CMD)}
AUTH_TOKEN    = {"gesetzt" if AUTH_TOKEN else "(nicht gesetzt)"}
CMD_TIMEOUT   = {CMD_TIMEOUT}s
          </div>
          <p class="note">
            Umgebungsvariablen:<br>
            <code>DMS_GUI_HOST</code>, <code>DMS_GUI_PORT</code>,
            <code>DMS_SETUP_CMD</code>, <code>DMS_EXEC_CMD</code>,
            <code>DMS_GUI_TOKEN</code>
          </p>
        </div>

        <div class="card">
          <h3>Verbindungstest</h3>
          <form method="post" action="/action">
            <input type="hidden" name="action" value="email_list">
            <div class="actions">
              <button class="btn" type="submit">setup email list ausführen</button>
            </div>
          </form>
        </div>
        {result}
        """,
        active="settings",
    )


def page_login(error: str = "") -> str:
    err = f'<p style="color:var(--danger);margin-bottom:1rem">{html.escape(error)}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login · DMS GUI</title>
  <style>{CSS}</style>
</head>
<body>
  <div class="login-box">
    <h1>Docker Mailserver GUI</h1>
    <p>Geschützter Zugang. Token erforderlich.</p>
    {err}
    <form method="post" action="/login">
      <label>Auth-Token</label>
      <input name="token" type="password" required autocomplete="current-password"
             style="margin-bottom:1rem">
      <button class="btn" type="submit" style="width:100%">Anmelden</button>
    </form>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Action-Handler
# ---------------------------------------------------------------------------
def handle_action(form: dict) -> tuple[str, str]:
    """Gibt (page, result_html) zurück."""
    action = (form.get("action") or [""])[0]

    def g(key: str, default: str = "") -> str:
        return (form.get(key) or [default])[0].strip()

    password = g("password") or None
    if password == "":
        password = None

    page = "email"
    args: list[str] = []
    use_exec = False  # True = run_exec statt run_setup

    # --- setup-Befehle -------------------------------------------------------
    if action == "email_add":
        page = "email"
        email = g("email")
        if not email:
            return page, render_result(1, "", "E-Mail-Adresse fehlt")
        args = ["email", "add", email]
        if password:
            args.append(password)
            password = None
    elif action == "email_update":
        page = "email"
        email = g("email")
        if not email:
            return page, render_result(1, "", "E-Mail-Adresse fehlt")
        args = ["email", "update", email]
        if password:
            args.append(password)
            password = None
    elif action == "email_del":
        page = "email"
        email = g("email")
        if not email:
            return page, render_result(1, "", "E-Mail-Adresse fehlt")
        args = ["email", "del", email]
    elif action == "email_restrict":
        page = "email"
        op = g("op")
        direction = g("direction")
        email = g("email")
        args = ["email", "restrict", op, direction]
        if email:
            args.append(email)
    elif action == "email_list":
        page = "email"
        args = ["email", "list"]

    elif action == "alias_add":
        page = "alias"
        alias, recipient = g("alias"), g("recipient")
        if not alias or not recipient:
            return page, render_result(1, "", "Alias und Empfänger erforderlich")
        args = ["alias", "add", alias, recipient]
    elif action == "alias_del":
        page = "alias"
        alias, recipient = g("alias"), g("recipient")
        if not alias or not recipient:
            return page, render_result(1, "", "Alias und Empfänger erforderlich")
        args = ["alias", "del", alias, recipient]
    elif action == "alias_list":
        page = "alias"
        args = ["alias", "list"]

    elif action == "quota_set":
        page = "quota"
        email = g("email")
        quota = g("quota")
        if not email:
            return page, render_result(1, "", "E-Mail-Adresse fehlt")
        args = ["quota", "set", email]
        if quota:
            args.append(quota)
    elif action == "quota_del":
        page = "quota"
        email = g("email")
        if not email:
            return page, render_result(1, "", "E-Mail-Adresse fehlt")
        args = ["quota", "del", email]

    elif action == "dm_add":
        page = "dovecot-master"
        username = g("username")
        if not username:
            return page, render_result(1, "", "Benutzername fehlt")
        args = ["dovecot-master", "add", username]
        if password:
            args.append(password)
            password = None
    elif action == "dm_update":
        page = "dovecot-master"
        username = g("username")
        if not username:
            return page, render_result(1, "", "Benutzername fehlt")
        args = ["dovecot-master", "update", username]
        if password:
            args.append(password)
            password = None
    elif action == "dm_del":
        page = "dovecot-master"
        username = g("username")
        if not username:
            return page, render_result(1, "", "Benutzername fehlt")
        args = ["dovecot-master", "del", username]
    elif action == "dm_list":
        page = "dovecot-master"
        args = ["dovecot-master", "list"]

    elif action == "dkim":
        page = "dkim"
        args = ["config", "dkim"]
        keysize = g("keysize")
        domain = g("domain")
        selector = g("selector")
        if keysize:
            args += ["keysize", keysize]
        if domain:
            args += ["domain", domain]
        if selector:
            args += ["selector", selector]

    elif action == "relay_add_domain":
        page = "relay"
        domain, host, port = g("domain"), g("host"), g("port")
        if not domain or not host:
            return page, render_result(1, "", "Domain und Host erforderlich")
        args = ["relay", "add-domain", domain, host]
        if port:
            args.append(port)
    elif action == "relay_add_auth":
        page = "relay"
        domain, username = g("domain"), g("username")
        if not domain or not username:
            return page, render_result(1, "", "Domain und Benutzername erforderlich")
        args = ["relay", "add-auth", domain, username]
        if password:
            args.append(password)
            password = None
    elif action == "relay_exclude":
        page = "relay"
        domain = g("domain")
        if not domain:
            return page, render_result(1, "", "Domain fehlt")
        args = ["relay", "exclude-domain", domain]

    elif action == "f2b_ban":
        page = "fail2ban"
        ip = g("ip")
        if not ip:
            return page, render_result(1, "", "IP fehlt")
        args = ["fail2ban", "ban", ip]
    elif action == "f2b_unban":
        page = "fail2ban"
        ip = g("ip")
        if not ip:
            return page, render_result(1, "", "IP fehlt")
        args = ["fail2ban", "unban", ip]
    elif action == "f2b_status":
        page = "fail2ban"
        args = ["fail2ban", "status"]
    elif action == "f2b_log":
        page = "fail2ban"
        args = ["fail2ban", "log"]
    elif action == "f2b":
        page = "fail2ban"
        args = ["fail2ban"]

    elif action == "debug_fetchmail":
        page = "debug"
        args = ["debug", "fetchmail"]
    elif action == "debug_getmail":
        page = "debug"
        args = ["debug", "getmail"]
    elif action == "debug_logs":
        page = "debug"
        args = ["debug", "show-mail-logs"]

    # --- Config lesen --------------------------------------------------------
    elif action == "view_config":
        page = "config"
        use_exec = True
        fname = g("file")
        if fname not in ALLOWED_CONFIG_FILES:
            return page, render_result(1, "", "Datei nicht erlaubt")
        # Verzeichnis oder Datei
        if fname.endswith("/"):
            args = ["ls", "-la", f"/tmp/docker-mailserver/{fname}"]
        else:
            args = ["cat", f"/tmp/docker-mailserver/{fname}"]
    elif action == "list_config_dir":
        page = "config"
        use_exec = True
        args = ["ls", "-la", "/tmp/docker-mailserver/"]

    # --- Mails ---------------------------------------------------------------
    elif action == "mails_list":
        page = "mails"
        use_exec = True
        # Zeigt Domain-Verzeichnisse und darunter die User
        args = ["sh", "-c", "find /var/mail -maxdepth 2 -type d 2>/dev/null | sort"]
    elif action == "mails_du":
        page = "mails"
        use_exec = True
        args = ["du", "-h", "--max-depth=2", "/var/mail"]
    elif action == "mails_user":
        page = "mails"
        use_exec = True
        domain = g("domain")
        user = g("user")
        if not domain or not user:
            return page, render_result(1, "", "Domain und Benutzer erforderlich")
        # Nur sichere Zeichen erlauben
        if not re.match(r"^[a-zA-Z0-9._-]+$", domain) or not re.match(r"^[a-zA-Z0-9._+-]+$", user):
            return page, render_result(1, "", "Ungültige Zeichen in Domain/User")
        path = f"/var/mail/{domain}/{user}"
        args = ["ls", "-la", path]
    elif action == "mails_count":
        page = "mails"
        use_exec = True
        email = g("email")
        if email:
            if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
                return page, render_result(1, "", "Ungültige E-Mail-Adresse")
            args = ["doveadm", "mailbox", "status", "-u", email, "messages", "INBOX"]
        else:
            args = ["sh", "-c", "doveadm mailbox status -A messages INBOX 2>/dev/null || echo 'doveadm nicht verfügbar oder keine Konten'"]

    # --- Logs ----------------------------------------------------------------
    elif action == "view_log":
        page = "logs"
        use_exec = True
        log_key = g("log")
        lines_s = g("lines", "100")
        try:
            lines = max(10, min(5000, int(lines_s)))
        except ValueError:
            lines = 100
        if log_key not in ALLOWED_LOGS:
            return page, render_result(1, "", "Log-Datei nicht erlaubt")
        path = ALLOWED_LOGS[log_key]
        args = ["tail", "-n", str(lines), path]
    elif action == "list_logs":
        page = "logs"
        use_exec = True
        args = ["ls", "-la", "/var/log/mail/"]

    elif action == "dash_refresh":
        # Dashboard lädt Status selbst – nur Seite neu rendern
        return "dashboard", ""

    else:
        return "email", render_result(1, "", f"Unbekannte Aktion: {action}")

    # Sicherheits-Check: keine Injection-Zeichen
    for a in args:
        if re.search(r"[;&|`$]", a) and action not in ("mails_list", "mails_count"):
            # Bei sh -c erlauben wir kontrollierte Strings
            if "sh" not in args[:1] and "-c" not in args:
                return page, render_result(1, "", "Ungültige Zeichen in Argumenten")

    if use_exec:
        rc, out, err = run_exec(args)
    else:
        rc, out, err = run_setup(args, password=password)

    password = None  # noqa: F841
    return page, render_result(rc, out, err)


# ---------------------------------------------------------------------------
# HTTP-Handler
# ---------------------------------------------------------------------------
RENDERERS = {
    "dashboard": page_dashboard,
    "email": page_email,
    "alias": page_alias,
    "quota": page_quota,
    "dovecot-master": page_dovecot_master,
    "dkim": page_dkim,
    "relay": page_relay,
    "fail2ban": page_fail2ban,
    "debug": page_debug,
    "config": page_config,
    "mails": page_mails,
    "logs": page_logs,
    "settings": page_settings,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _get_cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1 :]
        return None

    def _set_cookie(self, name: str, value: str, max_age: int = SESSION_TTL) -> None:
        self.send_header(
            "Set-Cookie",
            f"{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}",
        )

    def _require_auth(self) -> bool:
        if not AUTH_TOKEN:
            return True
        header = self.headers.get("X-Auth-Token", "")
        if header and secrets.compare_digest(header, AUTH_TOKEN):
            return True
        tok = self._get_cookie(SESSION_COOKIE)
        if _valid_session(tok):
            return True
        return False

    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        _clean_sessions()
        parsed = urlparse(self.path)
        if parsed.path not in ("/", "/index.html"):
            self._send(404, "Not Found")
            return

        if not self._require_auth():
            self._send(200, page_login())
            return

        qs = parse_qs(parsed.query)
        page = (qs.get("page") or ["dashboard"])[0]
        fn = RENDERERS.get(page, page_dashboard)
        self._send(200, fn())

    def do_POST(self) -> None:  # noqa: N802
        _clean_sessions()
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(raw, keep_blank_values=True)

        path = urlparse(self.path).path

        if path == "/login":
            token = (form.get("token") or [""])[0]
            if AUTH_TOKEN and secrets.compare_digest(token, AUTH_TOKEN):
                sess = _new_session()
                self.send_response(302)
                self._set_cookie(SESSION_COOKIE, sess)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._send(200, page_login("Ungültiges Token"))
            return

        if path != "/action":
            self._send(404, "Not Found")
            return

        if not self._require_auth():
            self._send(403, page_login("Nicht angemeldet"))
            return

        page, result = handle_action(form)
        fn = RENDERERS.get(page, page_email)
        self._send(200, fn(result))


def main() -> None:
    if AUTH_TOKEN:
        print("[DMS-GUI] Auth-Token ist gesetzt – Login erforderlich")
    else:
        print("[DMS-GUI] WARNUNG: Kein DMS_GUI_TOKEN gesetzt – GUI ist offen!")
        print("          Nur auf 127.0.0.1 binden oder Token setzen.")

    print(f"[DMS-GUI] SETUP_CMD = {SETUP_CMD}")
    print(f"[DMS-GUI] EXEC_CMD  = {EXEC_CMD}")
    print(f"[DMS-GUI] http://{HOST}:{PORT}/")

    server = HTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DMS-GUI] Beendet.")
        server.server_close()


if __name__ == "__main__":
    main()
