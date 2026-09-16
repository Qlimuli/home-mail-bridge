FROM python:3.12-alpine

# Minimale Runtime + Tools für Status
RUN apk add --no-cache bash curl docker-cli tzdata \
    && pip install --no-cache-dir --upgrade pip

WORKDIR /app
COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static

# Leichte Krypto-Libs (bcrypt + cryptography/Fernet)
RUN pip install --no-cache-dir \
    flask==3.0.3 \
    bcrypt==4.2.0 \
    cryptography==43.0.1

ENV PYTHONUNBUFFERED=1
EXPOSE 18880

CMD ["python", "/app/app.py"]
