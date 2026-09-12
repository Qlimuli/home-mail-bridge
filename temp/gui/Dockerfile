# Lightweight GUI for docker-mailserver administration
# Only read/write via docker exec into the mailserver container – no changes to DMS itself.
FROM python:3.12-alpine

# docker CLI needed for: docker exec -i mailserver setup …
RUN apk add --no-cache docker-cli

WORKDIR /app
COPY app.py /app/app.py

# Defaults (overridden by compose environment)
ENV DMS_GUI_HOST=0.0.0.0 \
    DMS_GUI_PORT=18880 \
    DMS_SETUP_CMD="docker exec -i mailserver setup" \
    DMS_EXEC_CMD="docker exec -i mailserver" \
    PYTHONUNBUFFERED=1

EXPOSE 18880

# Run as non-root where possible; docker.sock access may still require group
USER root
CMD ["python3", "/app/app.py"]
