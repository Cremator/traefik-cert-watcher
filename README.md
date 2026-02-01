# Traefik Cert Watcher

**Traefik Cert Watcher** is a lightweight Go application that monitors Traefik's `acme.json` certificates, writes them to a structured filesystem layout, and automatically restarts Docker containers using those certificates when they are updated.  

It is designed for environments where Traefik manages certificates, providing seamless integration with running Docker containers.

---

## Features

- Monitors `acme.json` for certificate updates using **fsnotify**.
- Stores certificates in a structured folder hierarchy per provider and domain.
- Computes certificate and key hashes to avoid unnecessary container restarts.
- Automatically restarts Docker containers labeled with a specific domain label when certificates change.
- Watches Docker events to track container lifecycle.
- Supports wildcard certificates.
- Safe atomic writes to avoid partial updates.

---

## Application Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--traefik-file` | `/traefik/acme.json` | Path to Traefik's `acme.json` file. |
| `--cert-dir` | `/certs` | Directory where certificates will be written. |
| `--docker-label` | `traefik.acme.cert` | Docker container label to monitor for certificate updates. |
| `--state-file` | `/certs/app_state.json` | Path to JSON file to store application state and certificate metadata. |

---

## Usage

```bash
# Run with default settings
./traefik-cert-watcher

# Specify custom paths
./traefik-cert-watcher \
  --traefik-file=/path/to/acme.json \
  --cert-dir=/path/to/certs \
  --docker-label=my.cert.label \
  --state-file=/path/to/state.json
