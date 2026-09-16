# Home-Mail-Bridge

**Extrem leichtes Mail-Deployment für Synology DS220j (und vergleichbar schwache NAS)**

- Benutzer per GUI anlegen
- Pro Benutzer echte **Gmail-** oder **GMX-Konten** verbinden
- Mails werden **direkt im Homelaufwerk** des Users abgelegt (`/volume1/homes/<user>/.Maildir`)
- Bestehende `.Maildir` vom alten Synology Mail Server werden automatisch erkannt und weiterverwendet
- Mail-Apps (Thunderbird, Apple Mail, Outlook, Smartphone …) verbinden sich per IMAP
- Alles über eine einfache Web-GUI konfigurierbar
- Sehr geringer Ressourcenverbrauch (Ziel: < 300 MB RAM gesamt)
- **Starke Passwort-Verschlüsselung** (bcrypt + Fernet)

---

## Voraussetzungen

- Synology DSM 7.x mit **Container Manager** (Docker)
- User-Home-Service aktiviert (Control Panel → Benutzer & Gruppe → Erweitert)
- Ports 143/993 (IMAP) und optional 110/995 (POP3) sowie 18880 (GUI) freigeben
- Für die K8s-Mail-App ohne TLS: IMAP-Port 143 verwenden und TLS/SSL deaktivieren. Port 143 akzeptiert Plain IMAP sowie STARTTLS; Port 993 bleibt für TLS-Clients verfügbar.
- Für Gmail: App-Passwort (2FA muss aktiv sein)

---

## Installation auf der Synology

### 1. Ordner anlegen

Im File Station (oder per SSH):

```bash
mkdir -p /volume1/docker/home-mail-bridge
# Das komplette Deployment hierher kopieren
```

### 2. Homes-Pfad prüfen

Standard ist `/volume1/homes`.  
Falls dein Volume anders heißt, in der `docker-compose.yml` alle Vorkommen von `/volume1/homes` anpassen.

### 3. Self-Signed Zertifikat erzeugen

```bash
cd /volume1/docker/home-mail-bridge
chmod +x scripts/generate-ssl.sh
./scripts/generate-ssl.sh
```

### 4. Sicherheitsschlüssel setzen (wichtig!)

Lege eine `.env`-Datei an oder trage die Werte direkt in der `docker-compose.yml` ein:

```bash
# Starke Tokens erzeugen
python3 -c "import secrets; print('GUI_TOKEN=' + secrets.token_urlsafe(48))"
python3 -c "import secrets; print('MASTER_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('GUI_SECRET=' + secrets.token_hex(32))"
```

Beispiel `.env`:

```env
GUI_TOKEN=dein-sehr-langer-zufaelliger-token-mindestens-32-zeichen
MASTER_KEY=64-zeichen-hex-key-aus-dem-befehl-oben
GUI_SECRET=weiterer-langer-key
TZ=Europe/Berlin
SYNC_INTERVAL=300
```

- **GUI_TOKEN**: Pflicht für Produktion – schützt die Web-Oberfläche
- **MASTER_KEY**: verschlüsselt die Gmail/GMX-App-Passwörter at-rest (Fernet/AES). Leer = automatischer Key in `data/master.key`
- **GUI_SECRET**: Flask-Session-Key

### 5. Projekt starten

Im **Container Manager** → **Projekt** → **Erstellen**:

- Projektname: `home-mail-bridge`
- Pfad: `/volume1/docker/home-mail-bridge`
- Die vorhandene `docker-compose.yml` wird erkannt → Deploy

Alternativ per SSH:

```bash
cd /volume1/docker/home-mail-bridge
docker compose up -d --build
```

### 6. GUI öffnen

```
http://<IP-deiner-NAS>:18880
```

Mit dem gesetzten Token einloggen.

---

## Sicherheit – was ist implementiert

| Bereich | Maßnahme |
|---------|----------|
| **Lokale IMAP-Passwörter** | bcrypt (cost 12) → Dovecot-Schema `{BLF-CRYPT}`. Niemals Klartext in `users.json` oder `passwd`. |
| **Gmail / GMX App-Passwörter** | Fernet (AES-128-CBC + HMAC-SHA256) verschlüsselt in `users.json`. Werden nur kurz im Speicher entschlüsselt, wenn die `.mbsyncrc` generiert wird. |
| **Config-Dateien** | `users.json`, `passwd`, `*.mbsyncrc` → Dateirechte `0600` |
| **GUI-Zugang** | Token-Auth (GUI_TOKEN). Ohne Token ist die GUI offen – in Produktion **immer setzen**. |
| **Transport** | IMAPS (993) + STARTTLS/Plain IMAP (143), TLS ≥ 1.2 für TLS-Verbindungen |
| **Master-Key** | Entweder per `MASTER_KEY`-Env oder persistent in `data/master.key` (0600) |

### Was du zusätzlich tun solltest

1. **Synology Antivirus** (Antivirus Essential / Official) auf den Homes-Ordner aktivieren – das ist der richtige Ort für Virenschutz der Maildir-Dateien. Ein eigener ClamAV-Container wäre auf der DS220j zu schwer.
2. **GUI nicht ins Internet** freigeben (oder nur hinter Reverse-Proxy + Auth / VPN).
3. Regelmäßig `GUI_TOKEN` und ggf. `MASTER_KEY` rotieren (bei Key-Wechsel müssen Provider-Konten neu hinterlegt werden).
4. Dateirechte der Deploy-Ordner prüfen: nur der Docker-User und root sollten schreiben können.
5. Plain IMAP auf Port 143 nur im vertrauenswürdigen LAN/VPN nutzen und den Port nicht ins Internet weiterleiten. Bei Plain IMAP werden Benutzername und Passwort unverschlüsselt übertragen.

### Was bewusst **nicht** drin ist

- ClamAV / SpamAssassin im Stack → zu RAM-hungrig für 512 MB
- Vollwertiger SMTP-Server → Clients sollen den Provider-SMTP nutzen
- Webmail → optional später (z. B. SnappyMail) nachrüstbar

---

## Bedienung

1. **Benutzer anlegen**  
   Lokaler Benutzername + Passwort (mind. 10 Zeichen). Das Passwort wird sofort bcrypt-gehasht und gilt für den IMAP-Login in den Mail-Apps.

2. **Bestehende .Maildir**  
   Beim Anlegen wird geprüft, ob schon eine `.Maildir` im Home liegt.  
   Mit dem Button „Prüfen / migrieren“ kannst du den Status aktualisieren.

3. **Gmail / GMX verbinden**  
   Beim jeweiligen Benutzer auf „+ Gmail / GMX / Custom verbinden“ klicken.  
   - Gmail → App-Passwort eintragen  
   - GMX → normales Passwort oder App-Passwort  
   Die Zugangsdaten werden **verschlüsselt** gespeichert. Der Sync startet automatisch (alle 5 Minuten, einstellbar).

4. **Passwort ändern**  
   In der Benutzerzeile unter „Passwort ändern“ möglich – neuer bcrypt-Hash wird sofort geschrieben.

5. **Mail-App konfigurieren**  
   - IMAP-Server: IP der Synology
   - Port: 143 und TLS/SSL deaktiviert, wenn die Mail-App kein TLS unterstützt (nur LAN/VPN)
   - Alternativ: Port 993 mit SSL/TLS für normale Mail-Clients
   - Benutzername / Passwort: die lokalen Daten aus der GUI
   - SMTP: am besten **direkt den Provider** verwenden (smtp.gmail.com bzw. mail.gmx.net)

---

## Ressourcen-Hinweise (DS220j)

| Container   | RAM-Limit | CPU-Limit |
|-------------|-----------|-----------|
| dovecot     | 128 MB    | 0.5       |
| sync        |  96 MB    | 0.4       |
| gui         |  96 MB    | 0.3       |

Gesamt deutlich unter 300 MB.

---

## Wichtige Dateien

```
home-mail-bridge/
├── docker-compose.yml
├── .env.example
├── config/
│   ├── dovecot/          # Dovecot-Konfiguration
│   ├── mbsync/           # pro User generierte .mbsyncrc (0600, temporär entschlüsselte Credentials)
│   └── users/            # users.json (verschlüsselte Secrets) + passwd (bcrypt)
├── gui/                  # Web-Oberfläche
├── sync/                 # mbsync-Service
├── scripts/
│   └── generate-ssl.sh
└── data/
    ├── dovecot-ssl/      # Zertifikat
    └── master.key        # Fernet-Key (falls kein MASTER_KEY in env)
```

---

## Troubleshooting

- **Permission denied auf Homes**  
  Der Container mappt auf UID 1000. Homes-Berechtigungen prüfen.

- **Sync holt keine Mails**  
  - App-Passwort bei Gmail korrekt?  
  - In der GUI „Sync jetzt anstoßen“ klicken  
  - Logs: `docker logs home-mail-sync`

- **IMAP-Login schlägt fehl**  
  - `docker logs home-mail-dovecot`  
  - Prüfen, ob der User in `config/users/passwd` mit `{BLF-CRYPT}` steht

- **Nach Update alte Klartext-Passwörter**  
  Beim ersten Start nach dem Update werden bestehende Klartext-Einträge automatisch in bcrypt bzw. Fernet migriert.

- **MASTER_KEY verloren**  
  Provider-Konten müssen neu hinterlegt werden (die verschlüsselten `remote_pass_enc` sind sonst nicht mehr lesbar).

---

## Was bewusst weggelassen wurde

- Vollwertiger SMTP-Server (Postfix) → Clients nutzen Provider-SMTP
- Spam-/Virenschutz im Container → Synology Antivirus auf Homes nutzen
- LDAP/Active Directory → einfache lokale Benutzer
- Webmail → optional später ergänzbar

Das hält den Stack klein, sicher und stabil auf dem DS220j.
