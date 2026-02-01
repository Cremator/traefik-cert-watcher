# Traefik Cert Watcher

**Traefik Cert Watcher** is a lightweight Go application that monitors Traefik's `acme.json` certificates, writes them to a structured filesystem layout, and automatically restarts Docker containers using those certificates when they are updated.  

It is designed for environments where Traefik manages certificates, and you want seamless integration with running Docker containers.

---

## Features

- Monitors `acme.json` for certificate updates using **fsnotify**.
- Stores certificates in a structured folder per provider and domain.
- Computes certificate and key hashes to avoid unnecessary container restarts.
- Automatically restarts Docker containers labeled with a specific domain label when certificates change.
- Watches Docker events to track container lifecycle.
- Supports wildcard certificates.
- Safe atomic writes to avoid partial updates.

---
