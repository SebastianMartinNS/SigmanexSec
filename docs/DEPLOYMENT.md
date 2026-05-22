# SAP-Pentest — Deployment guide

> Production-grade deployment of SAP-Pentest. The dev bootstrap (laptop,
> single user, no TLS) is covered by [`INSTALL.md`](INSTALL.md). This
> document is for setting the platform up on a hardened bastion VM or
> a small Kubernetes namespace so it can carry real engagements.

## 1. Decisions to make before you install

| Question | Recommendation |
|---|---|
| Single operator or team? | Multi-user via `SAP_DASHBOARD_USERS` JSON; one entry per analyst. |
| Where do operators connect from? | Always behind TLS. Either bind the dashboard to `127.0.0.1` and front it with nginx / Caddy / Cloudflare Tunnel, or terminate TLS via cert-manager in Kubernetes. |
| Where does the audit log live long-term? | Local disk (chattr +a on a separate mount) **plus** the external sink (`core/audit_sink.py`) shipping to remote syslog or WORM storage. |
| Does the platform need to use sudo-requiring tools (e.g. `nmap -sS`, `masscan`)? | Yes → install and start the sudo broker; configure `SAP_SUDO_BROKER_ENABLED=1`. No → keep the broker offline; the executor refuses privileged tools at runtime. |
| Will operators reach external LLM APIs (OpenAI / Anthropic)? | Default: NO. Enable only behind `--allow-external-llm` per engagement (v2.4+). |
| Disk capacity for tool outputs and audit? | Plan 50 GB minimum; tool outputs spill to `./runs/<run_id>/calls/`. |

## 2. Host bootstrap (bare metal / VM)

The supported reference platform is **Parrot Security 6.x on x86_64**
with optional NVIDIA GPU (kernel 6.17, driver 550 DKMS — see
`switch_to_kernel617.sh`). Ubuntu 22.04 / 24.04 also work; the install
scripts attempt to be distro-agnostic but `parrot_tools.yaml` assumes
Parrot package names.

```bash
# 1. System dependencies (Parrot OS package names).
sudo apt update
sudo apt install -y python3.13 python3.13-venv python3-pip \
                    build-essential cmake git curl jq \
                    nmap masscan nuclei sqlmap nikto ffuf gobuster \
                    sherlock holehe h8mail
# bwrap (v2.3+ sandboxing) and firejail (fallback)
sudo apt install -y bubblewrap firejail

# 2. Dedicated unprivileged user with a separate runtime dir.
sudo useradd --create-home --shell /usr/bin/bash sap
sudo mkdir -p /var/lib/sap /var/log/sap
sudo chown -R sap:sap /var/lib/sap /var/log/sap

# 3. Clone with submodule.
sudo -iu sap git clone --recursive https://github.com/SigmanexSec/SigmanexSec.git /var/lib/sap/pentest-workspace

# 4. Python venv + hash-locked install.
sudo -iu sap bash -c '
    cd /var/lib/sap/pentest-workspace
    python3.13 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install --require-hashes -r requirements.lock
    .venv/bin/pip install -e .            # editable so updates are git pull
'

# 5. Build the bundled llama.cpp fork (see docs/INSTALL.md §4).
sudo -iu sap bash -c '
    cd /var/lib/sap/pentest-workspace
    bash scripts/apply_llamacpp_patches.sh
    cd llama.cpp && cmake -B build -DGGML_CUDA=ON && cmake --build build -j
'

# 6. Operator credentials (hash to file mode 0600).
sudo -iu sap bash -c '
    cd /var/lib/sap/pentest-workspace
    cp .env.example .env
    chmod 600 .env
    python3.13 -c "import secrets; print(secrets.token_urlsafe(48))"  # paste as SAP_SESSION_SECRET
    # Edit .env to set SAP_DASHBOARD_USER and SAP_DASHBOARD_PASS.
'
```

## 3. systemd units (the canonical bare-metal layout)

A reference set of hardened units lives in `deploy/systemd/`. The
parameter file `deploy/systemd/sap-hardening.conf` applies:

* `ProtectSystem=strict` (root filesystem RO; only `/var/lib/sap`,
  `/var/log/sap`, `/run/sap`, `/tmp` writable).
* `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=yes` (W^X).
* `CapabilityBoundingSet=` (drop all by default; tools that need CAP_NET_RAW
  are run via the sudo broker, not from a capability-granted process).
* `SystemCallFilter=@system-service` + an explicit blocklist.

```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sap-llama.service sap-mcp@{recon,exploit,osint,blueteam,parrot,engagement}.service sap-dashboard.service sap-sudo-broker.service
```

Verify:

```bash
systemctl status sap-dashboard.service
curl -s http://127.0.0.1:8765/healthz   | jq
curl -s http://127.0.0.1:8765/readyz    | jq
for p in 9001 9002 9003 9004 9005 9006; do
  curl -sf "http://127.0.0.1:${p}/healthz" >/dev/null && echo "mcp:${p} ok"
done
```

## 4. TLS termination

The dashboard binds to `127.0.0.1` by default. Front it with a reverse
proxy that terminates TLS, sets `X-Forwarded-For` (rate-limit
attribution), and forwards to `127.0.0.1:8765`.

```nginx
server {
    listen 443 ssl http2;
    server_name sap.example.org;
    ssl_certificate     /etc/letsencrypt/live/sap.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sap.example.org/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $remote_addr;
        proxy_set_header   X-Forwarded-Proto https;
        # WebSocket support for live event stream.
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_read_timeout 3600s;
    }

    location = /healthz { proxy_pass http://127.0.0.1:8765; access_log off; }
    location = /readyz  { proxy_pass http://127.0.0.1:8765; access_log off; }
}
```

## 5. External audit sink (recommended for compliance)

A locally-stored audit chain is forensically useful but can be tampered
with by a root-equivalent attacker. Pair it with an off-host sink:

```bash
# Option A — remote syslog over TLS to a SIEM.
export SAP_AUDIT_SYSLOG_HOST=siem.example.org
export SAP_AUDIT_SYSLOG_PORT=6514
export SAP_AUDIT_SYSLOG_TLS=1
export SAP_AUDIT_SYSLOG_PROTO=tcp

# Option B — append-only file mirror owned by an auditor account.
sudo install -d -m 0750 -o auditor -g auditor /var/log/sap-audit-wormside
sudo chattr +a /var/log/sap-audit-wormside
export SAP_AUDIT_FILE_SINK=/var/log/sap-audit-wormside/audit.jsonl
```

Both can be enabled simultaneously. Failures in the sink path are
logged but **never** block the local append (we never silently drop an
audit record).

## 6. Containerised deployment (v3.0)

v3.0 ships a parametrised OCI image
[`deploy/podman/Containerfile.service`](../deploy/podman/Containerfile.service)
that builds the orchestrator **and** the six MCP servers from a single
Containerfile via `--build-arg SAP_SERVICE=...`. The dashboard keeps its
own image at [`deploy/podman/Containerfile.dashboard`](../deploy/podman/Containerfile.dashboard)
(unchanged since v2.3).

Build every image locally:

```bash
podman build --build-arg SAP_SERVICE=orchestrator \
    -t ghcr.io/sigmanexsec/sap-pentest-orchestrator:v3.0.0 \
    -f deploy/podman/Containerfile.service .

for s in recon exploit blueteam parrot engagement osint; do
    podman build --build-arg SAP_SERVICE=mcp-$s \
        -t ghcr.io/sigmanexsec/sap-pentest-mcp-$s:v3.0.0 \
        -f deploy/podman/Containerfile.service .
done

podman build -t ghcr.io/sigmanexsec/sap-pentest-dashboard:v3.0.0 \
    -f deploy/podman/Containerfile.dashboard .
```

The published reference compose stack lives at
[`deploy/compose/docker-compose.yml`](../deploy/compose/docker-compose.yml).
Quick bring-up:

```bash
cp deploy/compose/.env.example .env
$EDITOR .env                       # set ANTHROPIC_API_KEY +
                                   # CREDENTIAL_ENCRYPTION_PASSPHRASE
docker compose -f deploy/compose/docker-compose.yml up -d
docker compose -f deploy/compose/docker-compose.yml logs -f orchestrator
```

Verify provenance before the first pull:

```bash
cosign verify \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
    --certificate-identity-regexp 'https://github.com/SigmanexSec/.*' \
    ghcr.io/sigmanexsec/sap-pentest-orchestrator:v3.0.0
```

The compose stack also wires a local Prometheus instance scraping
`/metrics` and an opt-in OTel collector profile (`docker compose ...
--profile tracing up -d`). See
[`deploy/compose/prometheus.yml`](../deploy/compose/prometheus.yml)
and [`deploy/compose/otel-collector.yml`](../deploy/compose/otel-collector.yml).

Helm chart is deferred to v3.1 to keep the v3.0 maintenance surface
tight; in the meantime the same docker-compose can be translated to a
`kustomize` overlay if you need a Kubernetes deploy.

## 7. Backup and disaster recovery

Backed-up assets (priority order):

1. **`logs/audit.jsonl*`** — the audit chain. Backup is part of the
   regulatory story; loss of any segment breaks the chain. Snapshot
   nightly to off-host storage; rely on the external sink as the
   authoritative copy.
2. **`sessions/assessments.db`** — engagement state, findings,
   credentials store. Snapshot every 15 minutes; `aiosqlite` is safe
   to snapshot with `sqlite3 .backup`.
3. **`runs/<run_id>/`** — tool output spill. Snapshot nightly; older
   runs are pruned by `core/storage_gc.py`.
4. **`reports/`** — generated PDF / Markdown reports.
5. **`.env` + `~/.local/state/sap/session.key`** — credentials and
   session HMAC. Treat as secrets; keep one off-host encrypted copy.

Restore drill: re-bootstrap a fresh VM following §2 + §3, then untar the
backup over `/var/lib/sap`. Run `python -m core.audit_log verify` to
confirm chain integrity.

## 8. Upgrade procedure

```bash
sudo systemctl stop sap-dashboard sap-mcp@* sap-llama sap-sudo-broker
sudo -iu sap bash -c '
    cd /var/lib/sap/pentest-workspace
    git pull --rebase
    git submodule update --recursive
    .venv/bin/pip install --upgrade --require-hashes -r requirements.lock
    .venv/bin/pip install -e .   # re-link entry points
'
# Re-apply llama.cpp patches if the submodule moved.
sudo -iu sap bash scripts/apply_llamacpp_patches.sh
sudo systemctl daemon-reload
sudo systemctl start sap-llama sap-sudo-broker sap-mcp@{recon,exploit,osint,blueteam,parrot,engagement} sap-dashboard
```

Always read the version's `CHANGELOG.md` entry first — major versions
may require migration scripts under `scripts/migrate_*.py`.

## 9. Smoke tests after install

```bash
# 1. Liveness on every component.
curl -fs http://127.0.0.1:8765/healthz
curl -fs http://127.0.0.1:8765/readyz | jq '.ready == true'
for p in 9001 9002 9003 9004 9005 9006; do
  curl -fs http://127.0.0.1:${p}/healthz >/dev/null && echo "mcp:${p} ok"
done

# 2. Audit chain integrity.
sudo -iu sap .venv/bin/python -m core.audit_log verify

# 3. CLI works.
sudo -iu sap /var/lib/sap/pentest-workspace/.venv/bin/sap-pentest --help

# 4. Run the dashboard auth probe (replace placeholder).
curl -fs -u "${SAP_DASHBOARD_USER}:${SAP_DASHBOARD_PASS}" http://127.0.0.1:8765/api/auth/me | jq
```

If any of these fail, jump to [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
