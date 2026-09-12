# DMS Administration GUI

Web-Oberfläche für docker-mailserver. Läuft als optionaler Service neben dem Mailserver.

## Start mit dem Haupt-Compose

Im Projektverzeichnis:

```bash
# Optional: Token setzen (empfohlen)
export DMS_GUI_TOKEN="$(openssl rand -hex 24)"
echo "DMS_GUI_TOKEN=${DMS_GUI_TOKEN}" >> .env   # oder in mailserver.env / eigene Datei

docker compose up -d
```

GUI erreichbar unter: **http://\<host\>:18880/**

## Umgebung

| Variable | Standard | Bedeutung |
|----------|----------|-----------|
| `DMS_GUI_TOKEN` | *(leer)* | Login-Token (stark empfohlen) |
| `DMS_SETUP_CMD` | `docker exec -i mailserver setup` | setup-CLI |
| `DMS_EXEC_CMD` | `docker exec -i mailserver` | read-only Befehle |
| `DMS_GUI_PORT` | `18880` | Port im Container |

## Sicherheit

- Bindet standardmäßig auf allen Interfaces im Container; über Compose-Port-Mapping steuern.
- Docker-Socket wird **read-only** gemountet.
- Passwörter nur über sichere Formularfelder, nie geloggt.
- Config/Mails/Logs nur lesend (Whitelist).

Die GUI ändert **nichts** an der Grundfunktionsweise von docker-mailserver.
