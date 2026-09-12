---
title: 'Tutorials | Mailbox Compression'
---

## Overview

!!! warning "This is a community contributed guide"

    This content is entirely community supported. If you find errors, please open an issue and provide a PR.

Dovecot provides a plugin for _mailbox compression_. This plugin enables support to read messages stored in a compressed format and to write new messages in a compressed format.

This guide applies to DMS 16 and later, which uses Dovecot 2.4 and the [`mail-compress` plugin][dovecot::plugin::mail-compress].

!!! tip "Compression algorithm"

    The plugin supports several compression algorithms. For a good balance between compression ratio and performance, this guide uses `zstd`. See the [Dovecot documentation][dovecot::plugin::mail-compress] for the other supported algorithms.

!!! info "Raising the memory limit to avoid errors"

    Depending on usage, compression may exceed Dovecot's [default process memory limit][dovecot::config::default-vsz-limit] of 256 MiB. The configuration below shows how to raise that limit globally if necessary; tune it for your environment.

[dovecot::plugin::mail-compress]: https://doc.dovecot.org/2.4.1/core/plugins/mail_compress.html
[dovecot::config::default-vsz-limit]: https://doc.dovecot.org/2.4.1/core/summaries/settings.html#default_vsz_limit

## Setup

Create `docker-data/dms/config/dovecot/90-mail-compress.conf` with the following configuration:

```conf
# Enable the compression plugin globally for reading and writing:
mail_plugins {
  mail_compress = yes
}

# Compress new messages with zstd when they are saved:
mail_compress_write_method = zstd

# Uncomment and tune this only if Dovecot's default limit is too low:
# default_vsz_limit = 1G
```

Alternatively, add the same configuration to `docker-data/dms/config/dovecot.cf`. DMS copies that file to Dovecot's local configuration.

Add the configuration file to the `mailserver` service in your `compose.yaml`:

```yaml
services:
  mailserver:
    volumes:
      - ./docker-data/dms/config/dovecot/90-mail-compress.conf:/etc/dovecot/conf.d/90-mail-compress.conf:ro
```

Restart DMS so it loads the new configuration:

```console
$ docker compose up -d --force-recreate
```

### Verify your configuration

After restarting the DMS container, check that `mail_compress` is enabled for the services that read and write mail:

```console
$ docker compose exec mailserver doveconf -f protocol=lmtp mail_plugins
mail_plugins {
  mail_compress = yes
  ...
}

$ docker compose exec mailserver doveconf -f protocol=imap mail_plugins
mail_plugins {
  mail_compress = yes
  ...
}

$ docker compose exec mailserver doveconf -f protocol=pop3 mail_plugins
mail_plugins {
  mail_compress = yes
  ...
}
```

To verify that new mail is actually stored compressed, send a test message to an existing account and inspect the resulting Maildir file:

```console
$ docker compose exec mailserver swaks \
    --server 0.0.0.0 \
    --from hello@not-relevant.test \
    --to john.doe@example.com
$ file docker-data/dms/mail-data/example.com/john.doe/new/*
...: Zstandard compressed data ...
```

## Troubleshooting

### Cached message size larger than expected

> ```
> dms dovecot: indexer-worker(john.doe@example.com)<1662><PLy3NgU3z2h8BgAAPDOPJQ:vWooFAY3z2h>: Error: Mailbox INBOX: UID=3: read(/var/mail/example.com/john.doe/cur/1758395999.M371909P1818.mail.example.com,S=30343,W=30821:2,S) failed: Cached message size larger than expected (30343 > 16567, box=INBOX, UID=3) (read reason=mail stream)
>
> dms dovecot: indexer-worker(john.doe@example.com)<1662><PLy3NgU3z2h8BgAAPDOPJQ:vWooFAY3z2h>: Error: Mailbox INBOX: Deleting corrupted cache record uid=3: UID 3: Broken physical size in mailbox INBOX: read(/var/mail/example.com/john.doe/cur/1758395999.M371909P1818.mail.example.com,S=30343,W=30821:2,S) failed: Cached message size larger than expected (30343 > 16567, box=INBOX, UID=3)
> ```

This can occur when importing mailboxes from another Dovecot system that were already compressed before the `mail-compress` plugin was enabled. Ensure the plugin is loaded and restart DMS with `docker compose up -d --force-recreate`.
