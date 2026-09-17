#!/usr/bin/env python3
"""
Home-Mail-Bridge GUI – leichte Web-Oberfläche für DS220j
- Benutzer anlegen / löschen
- Gmail / GMX / Custom IMAP verbinden
- mbsync-Configs generieren
- Bestehende .Maildir übernehmen
- Status von Dovecot + Sync anzeigen

Sicherheit:
- Lokale IMAP-Passwörter: bcrypt (BLF-CRYPT) – nie im Klartext gespeichert
- Provider-Passwörter (Gmail/GMX): Fernet-verschlüsselt at-rest (AES-128-CBC + HMAC)
- Config-Dateien: mode 0600
- Strenge Username-Validierung, min. Passwortlänge
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import subprocess
from datetime import datetime
from functools import wraps
from pathlib import Path

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
# Starker Session-Key (mindestens 32 Bytes)
_secret = os.environ.get("GUI_SECRET", "").strip()
if not _secret or len(_secret) < 32:
    _secret = secrets.token_hex(32)
app.secret_key = _secret

# ---------------------------------------------------------------------------
# Pfade & Konfiguration
# ---------------------------------------------------------------------------
CONFIG_ROOT = Path(os.environ.get("CONFIG_ROOT", "/config"))
USERS_DIR = CONFIG_ROOT / "users"
MBSYNC_DIR = CONFIG_ROOT / "mbsync"
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
HOMES_BASE = Path(os.environ.get("HOMES_BASE", "/homes"))
GUI_TOKEN = os.environ.get("GUI_TOKEN", "").strip()
DOVECOT_CONTAINER = os.environ.get("DOVECOT_CONTAINER", "home-mail-dovecot")
SYNC_CONTAINER = os.environ.get("SYNC_CONTAINER", "home-mail-sync")

USERS_FILE = USERS_DIR / "users.json"
PASSWD_FILE = USERS_DIR / "passwd"
MASTER_KEY_FILE = DATA_DIR / "master.key"

# Provider-Presets
PROVIDERS = {
    "gmail": {
        "name": "Gmail",
        "host": "imap.gmail.com",
        "port": 993,
        "ssl": "IMAPS",
        "note": "App-Passwort erforderlich (2FA aktivieren → App-Passwörter)",
    },
    "gmx": {
        "name": "GMX",
        "host": "imap.gmx.net",
        "port": 993,
        "ssl": "IMAPS",
        "note": "Normales Passwort oder App-Passwort möglich",
    },
    "custom": {
        "name": "Custom IMAP",
        "host": "",
        "port": 993,
        "ssl": "IMAPS",
        "note": "Eigene IMAP-Daten eingeben",
    },
}


# ---------------------------------------------------------------------------
# Kryptografie-Helfer
# ---------------------------------------------------------------------------
def _get_fernet() -> Fernet:
    """
    Liefert ein Fernet-Objekt (AES-128-CBC + HMAC-SHA256).
    Schlüssel wird aus MASTER_KEY (env) oder aus persistentem master.key geladen/erzeugt.
    """
    key_b64 = os.environ.get("MASTER_KEY", "").strip()
    if key_b64:
        # Erlaubt: roher 32-Byte-Key als urlsafe_b64 oder als Hex
        try:
            if len(key_b64) == 44 and key_b64.endswith("="):
                return Fernet(key_b64.encode("ascii"))
            # Hex → 32 Bytes → Fernet-Key
            raw = bytes.fromhex(key_b64) if len(key_b64) == 64 else base64.urlsafe_b64decode(key_b64)
            if len(raw) != 32:
                raise ValueError("MASTER_KEY muss 32 Bytes sein")
            return Fernet(base64.urlsafe_b64encode(raw))
        except Exception as e:
            raise RuntimeError(f"Ungültiger MASTER_KEY: {e}") from e

    # Persistenter Key in data/
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if MASTER_KEY_FILE.exists():
        key = MASTER_KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        MASTER_KEY_FILE.write_bytes(key)
        MASTER_KEY_FILE.chmod(0o600)
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    """Verschlüsselt einen String → urlsafe base64 Token."""
    if not plaintext:
        return ""
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    """Entschlüsselt einen Fernet-Token. Bei Fehler → leerer String."""
    if not token:
        return ""
    try:
        f = _get_fernet()
        return f.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):
        return ""


def hash_password(password: str) -> str:
    """Erzeugt einen bcrypt-Hash (kompatibel mit Dovecot BLF-CRYPT)."""
    # 12 Runden = guter Kompromiss Sicherheit / CPU auf ARM
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("ascii")  # $2b$12$...


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def ensure_dirs():
    USERS_DIR.mkdir(parents=True, exist_ok=True)
    MBSYNC_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        USERS_FILE.write_text("[]", encoding="utf-8")
        USERS_FILE.chmod(0o600)


def _secure_write(path: Path, content: str, mode: int = 0o600):
    """Schreibt Datei und setzt restriktive Rechte."""
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(mode)
    except OSError:
        pass  # auf manchen Bind-Mounts nicht möglich


def load_users() -> list[dict]:
    ensure_dirs()
    try:
        users = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

    # Einmalige Migration: altes Klartext-Passwort → bcrypt-Hash
    changed = False
    for u in users:
        if "password" in u and "password_hash" not in u:
            plain = u.pop("password")
            u["password_hash"] = hash_password(plain)
            changed = True
        # Alte Klartext-Remote-Passwörter verschlüsseln
        for acc in u.get("accounts", []):
            if "remote_pass" in acc and "remote_pass_enc" not in acc:
                plain = acc.pop("remote_pass")
                acc["remote_pass_enc"] = encrypt_secret(plain)
                changed = True
    if changed:
        save_users(users)
    return users


def save_users(users: list[dict]):
    ensure_dirs()
    # Nie Klartext-Passwörter persistieren
    clean = []
    for u in users:
        cu = {k: v for k, v in u.items() if k not in ("password",)}
        if "accounts" in cu:
            cu["accounts"] = [
                {k: v for k, v in a.items() if k != "remote_pass"}
                for a in cu["accounts"]
            ]
        clean.append(cu)
    _secure_write(USERS_FILE, json.dumps(clean, indent=2, ensure_ascii=False))
    regenerate_passwd(clean)
    regenerate_all_mbsync(clean)


def regenerate_passwd(users: list[dict]):
    """Erzeugt die Dovecot-Passwd-Datei mit bcrypt-Hashes (BLF-CRYPT)."""
    lines = []
    for u in users:
        pw_hash = u.get("password_hash", "")
        if not pw_hash:
            continue
        home = str(HOMES_BASE / u["username"])
        # Dovecot erkennt {BLF-CRYPT} automatisch
        line = f'{u["username"]}:{{BLF-CRYPT}}{pw_hash}:1000:1000::{home}::'
        lines.append(line)
    _secure_write(PASSWD_FILE, "\n".join(lines) + ("\n" if lines else ""))


def make_mbsyncrc(user: dict) -> str:
    """Erzeugt eine mbsyncrc für einen User (Provider-Passwörter werden entschlüsselt)."""
    username = user["username"]
    home = HOMES_BASE / username
    maildir = home / ".Maildir"
    accounts = user.get("accounts", [])

    if not accounts:
        return f"# Keine externen Konten für {username}\n"

    parts = [f"# Auto-generated for {username} – {datetime.now().isoformat()}"]
    parts.append("# Datei enthält entschlüsselte Provider-Credentials – Rechte 0600!")

    for i, acc in enumerate(accounts):
        store_remote = f"remote{i}"
        store_local = f"local{i}"
        channel = f"channel{i}"

        host = acc.get("host", "")
        port = acc.get("port", 993)
        remote_user = acc.get("remote_user", "")
        # Entschlüsseln nur im Speicher
        remote_pass = decrypt_secret(acc.get("remote_pass_enc", ""))
        if not remote_pass and acc.get("remote_pass"):
            # Fallback falls Migration noch nicht gelaufen
            remote_pass = acc.get("remote_pass", "")
        ssltype = acc.get("ssl", "IMAPS")

        # mbsync erwartet das Passwort im Klartext in der Config
        parts.append(f"""
IMAPAccount {store_remote}
Host {host}
Port {port}
User {remote_user}
Pass {remote_pass}
AuthMechs LOGIN
SSLType {ssltype}
PipelineDepth 20
Timeout 60
SSLVersions TLSv1.2 TLSv1.3

IMAPStore {store_remote}
Account {store_remote}

MaildirStore {store_local}
Path {maildir}/
Inbox {maildir}/
SubFolders Verbatim
Flatten .

Channel {channel}
Far :{store_remote}:
Near :{store_local}:
Patterns *
Create Near
Expunge Near
SyncState *
Sync Pull
""")
    return "\n".join(parts)


def regenerate_all_mbsync(users: list[dict]):
    # Alte Configs aufräumen
    for f in MBSYNC_DIR.glob("*.mbsyncrc"):
        f.unlink(missing_ok=True)
    for u in users:
        if u.get("accounts"):
            cfg = MBSYNC_DIR / f"{u['username']}.mbsyncrc"
            _secure_write(cfg, make_mbsyncrc(u), mode=0o600)


def ensure_maildir(username: str) -> Path:
    """Stellt sicher, dass .Maildir existiert (Migration / Neuanlage)."""
    home = HOMES_BASE / username
    maildir = home / ".Maildir"
    if not home.exists():
        home.mkdir(parents=True, exist_ok=True)
    if not maildir.exists():
        # Leere Maildir-Struktur anlegen (Maildir++)
        for sub in ("cur", "new", "tmp"):
            (maildir / sub).mkdir(parents=True, exist_ok=True)
        # Standard-Ordner
        for folder in ("Drafts", "Sent", "Trash", "Junk", "Archive"):
            for sub in ("cur", "new", "tmp"):
                (maildir / f".{folder}" / sub).mkdir(parents=True, exist_ok=True)
    return maildir


def docker_status(container: str) -> str:
    try:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", container],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unreachable"


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if GUI_TOKEN:
            token = session.get("token") or request.headers.get("X-Auth-Token")
            if token != GUI_TOKEN:
                return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if not GUI_TOKEN:
        session["token"] = "open"
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        if request.form.get("token") == GUI_TOKEN:
            session["token"] = GUI_TOKEN
            session.permanent = True
            return redirect(url_for("dashboard"))
        flash("Falscher Token", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_auth
def dashboard():
    users = load_users()
    # Für die Anzeige nie entschlüsselte Passwörter mitgeben
    safe_users = []
    for u in users:
        su = dict(u)
        su.pop("password_hash", None)
        su.pop("password", None)
        accounts = []
        for a in su.get("accounts", []):
            sa = {k: v for k, v in a.items() if k not in ("remote_pass", "remote_pass_enc")}
            sa["has_password"] = bool(a.get("remote_pass_enc") or a.get("remote_pass"))
            accounts.append(sa)
        su["accounts"] = accounts
        safe_users.append(su)

    dovecot = docker_status(DOVECOT_CONTAINER)
    sync = docker_status(SYNC_CONTAINER)
    return render_template(
        "dashboard.html",
        users=safe_users,
        dovecot_status=dovecot,
        sync_status=sync,
        homes_base=str(HOMES_BASE),
        providers=PROVIDERS,
        imap_port=int(os.environ.get("IMAP_PORT", "143")),
        imaps_port=int(os.environ.get("IMAPS_PORT", "993")),
    )


@app.route("/user/add", methods=["POST"])
@require_auth
def user_add():
    # Groß-/Kleinschreibung beibehalten (Synology-Homes sind case-sensitiv)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not re.match(r"^[A-Za-z0-9._-]{1,32}$", username):
        flash("Ungültiger Benutzername (nur A-Z a-z 0-9 . _ -, max. 32 Zeichen)", "error")
        return redirect(url_for("dashboard"))
    if not password or len(password) < 10:
        flash("Passwort muss mindestens 10 Zeichen haben", "error")
        return redirect(url_for("dashboard"))
    if len(password) > 128:
        flash("Passwort zu lang", "error")
        return redirect(url_for("dashboard"))

    users = load_users()
    # Vergleich case-insensitive, speichern aber mit Original-Schreibweise
    if any(u["username"].lower() == username.lower() for u in users):
        flash("Benutzer existiert bereits", "error")
        return redirect(url_for("dashboard"))

    # Home + .Maildir anlegen / bestehende übernehmen
    maildir = ensure_maildir(username)
    existing = "ja" if any(maildir.iterdir()) else "neu"

    users.append(
        {
            "username": username,
            "password_hash": hash_password(password),
            "created": datetime.now().isoformat(timespec="seconds"),
            "accounts": [],
            "maildir_existing": existing,
        }
    )
    save_users(users)
    flash(f"Benutzer {username} angelegt (Maildir: {existing})", "ok")
    return redirect(url_for("dashboard"))


@app.route("/user/<username>/password", methods=["POST"])
@require_auth
def user_password(username):
    """IMAP-Passwort eines Users ändern."""
    password = request.form.get("password", "").strip()
    if not password or len(password) < 10:
        flash("Passwort muss mindestens 10 Zeichen haben", "error")
        return redirect(url_for("dashboard"))

    users = load_users()
    user = next((u for u in users if u["username"] == username), None)
    if not user:
        flash("User nicht gefunden", "error")
        return redirect(url_for("dashboard"))

    user["password_hash"] = hash_password(password)
    save_users(users)
    flash(f"Passwort für {username} geändert", "ok")
    return redirect(url_for("dashboard"))


@app.route("/user/<username>/delete", methods=["POST"])
@require_auth
def user_delete(username):
    users = load_users()
    users = [u for u in users if u["username"] != username]
    save_users(users)
    # mbsync-Config löschen
    (MBSYNC_DIR / f"{username}.mbsyncrc").unlink(missing_ok=True)
    flash(f"Benutzer {username} gelöscht (Home-Verzeichnis bleibt erhalten)", "ok")
    return redirect(url_for("dashboard"))


@app.route("/user/<username>/account", methods=["POST"])
@require_auth
def account_add(username):
    users = load_users()
    user = next((u for u in users if u["username"] == username), None)
    if not user:
        flash("User nicht gefunden", "error")
        return redirect(url_for("dashboard"))

    provider = request.form.get("provider", "custom")
    preset = PROVIDERS.get(provider, PROVIDERS["custom"])

    remote_pass = request.form.get("remote_pass", "").strip()
    if not remote_pass:
        flash("Remote-Passwort ist Pflicht", "error")
        return redirect(url_for("dashboard"))

    acc = {
        "provider": provider,
        "host": request.form.get("host") or preset["host"],
        "port": int(request.form.get("port") or preset["port"]),
        "ssl": request.form.get("ssl") or preset["ssl"],
        "remote_user": request.form.get("remote_user", "").strip(),
        "remote_pass_enc": encrypt_secret(remote_pass),  # verschlüsselt speichern
        "label": request.form.get("label", provider).strip() or provider,
    }

    if not acc["remote_user"]:
        flash("Remote-Benutzer ist Pflicht", "error")
        return redirect(url_for("dashboard"))

    user.setdefault("accounts", []).append(acc)
    save_users(users)
    flash(f"Konto {acc['label']} für {username} hinzugefügt – Sync startet automatisch", "ok")
    return redirect(url_for("dashboard"))


@app.route("/user/<username>/account/<int:idx>/delete", methods=["POST"])
@require_auth
def account_delete(username, idx):
    users = load_users()
    user = next((u for u in users if u["username"] == username), None)
    if user and 0 <= idx < len(user.get("accounts", [])):
        del user["accounts"][idx]
        save_users(users)
        flash("Konto entfernt", "ok")
    return redirect(url_for("dashboard"))


@app.route("/sync/now", methods=["POST"])
@require_auth
def sync_now():
    """Triggert einen sofortigen Sync-Lauf über Trigger-Datei (kein docker restart)."""
    try:
        trigger = MBSYNC_DIR / ".sync_now"
        trigger.write_text(datetime.now().isoformat(), encoding="utf-8")
        try:
            trigger.chmod(0o666)
        except OSError:
            pass
        flash("Sync angefordert – nächster Lauf startet in wenigen Sekunden", "ok")
    except Exception as e:
        flash(f"Sync-Trigger fehlgeschlagen: {e}", "error")
    return redirect(url_for("dashboard"))


@app.route("/user/<username>/migrate", methods=["POST"])
@require_auth
def migrate(username):
    maildir = ensure_maildir(username)
    status = "vorhanden" if any(maildir.iterdir()) else "leer angelegt"
    flash(f"Maildir für {username}: {status} ({maildir})", "ok")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ensure_dirs()
    # Master-Key initialisieren (falls noch keiner existiert)
    try:
        _get_fernet()
    except Exception as e:
        print(f"[gui] WARNUNG Master-Key: {e}")

    port = int(os.environ.get("GUI_PORT", "18880"))
    print(f"[gui] Home-Mail-Bridge GUI auf Port {port}")
    if GUI_TOKEN:
        print("[gui] Auth-Token aktiv")
    else:
        print("[gui] WARNUNG: Kein GUI_TOKEN gesetzt – jeder im Netz kann zugreifen!")
    print("[gui] Passwörter: lokale = bcrypt (BLF-CRYPT), Provider = Fernet-verschlüsselt")
    app.run(host="0.0.0.0", port=port, debug=False)
