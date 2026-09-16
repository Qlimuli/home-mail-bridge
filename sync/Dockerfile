FROM alpine:3.20

RUN apk add --no-cache isync ca-certificates tzdata bash findutils \
    && update-ca-certificates

# non-root
RUN adduser -D -u 1000 -g 1000 mailsync

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER mailsync
WORKDIR /home/mailsync

ENTRYPOINT ["/entrypoint.sh"]
