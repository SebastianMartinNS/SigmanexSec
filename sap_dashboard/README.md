# SAP Control Dashboard

A FastAPI control plane + minimal HTMX/Alpine/Tailwind UI to drive the
**Security Assessment Platform** end-to-end: pick an engagement, launch the
agent in Planning / Execution / Step mode, approve sudo-gated calls, browse
the Parrot OS tool catalogue, and inspect runtime settings.

## Quick start

```bash
# 1. install backend deps (one-time)
pip install -r requirements.txt --break-system-packages   # or use a venv

# 2. set HTTP Basic credentials (no default — refuses to start otherwise)
export SAP_DASHBOARD_USER=admin
export SAP_DASHBOARD_PASS='change-me'

# 3. (optional) set LLM credentials for agent runs
export ANTHROPIC_API_KEY=...   # or OPENAI_API_KEY / OPENAI_BASE_URL for llama.cpp

# 4. start MCP servers (separate terminal)
bash start_mcp_http.sh            # exposes recon/exploit/blueteam/parrot/engagement

# 5. start the dashboard
python cli.py dashboard --host 127.0.0.1 --port 8765
# or directly: uvicorn sap_dashboard.backend.app:app --reload --port 8765
```

Open http://127.0.0.1:8765/.

## TLS

The dashboard handles credentials and triggers privileged actions; **never**
expose it on a non-loopback interface without TLS. The CLI refuses to bind a
non-loopback host unless `--cert` and `--key` are provided:

```bash
python cli.py dashboard --host 0.0.0.0 --port 8765 --cert cert.pem --key key.pem
```

For LAN deployments prefer terminating TLS at a reverse proxy (Caddy / nginx)
and binding the dashboard to localhost.

## Authentication model

* HTTP Basic for v1 (set `dashboard.auth` in `config.yaml` or via env vars).
* WebSocket auth: client opens `wss://…/api/runs/{id}/events/ws` and sends
  `{ "type": "auth", "token": "<base64 user:pass>" }` as the first frame.
* Failed `/api/sudo/unlock` attempts are rate-limited per process (5 / 60 s).
* When `dashboard.auth` is unset, every API call returns **503** to prevent
  accidentally exposing the platform.

## API surface

See `/docs` (Swagger UI) when the dashboard is running. Highlights:

| Path                                             | Method | Purpose                          |
|--------------------------------------------------|--------|----------------------------------|
| `/api/engagements`                               | GET    | list engagements                  |
| `/api/engagements/{id}/run`                      | POST   | start an agent run                |
| `/api/runs/{id}` / `…/events/ws`                 | REST+WS| status & live events stream      |
| `/api/runs/{id}/approve`                         | POST   | resolve a Step-mode/sudo gate    |
| `/api/sudo/{status,unlock}` + DELETE `/api/sudo` |        | vault control plane              |
| `/api/parrot/tools`                              | GET    | declarative Parrot catalogue     |
| `/api/settings`                                  | GET/PATCH | runtime config view + overlay |

## Repository layout

```
sap_dashboard/
├── backend/
│   ├── app.py            # FastAPI app + security headers middleware
│   ├── deps.py           # singletons + HTTP Basic auth
│   ├── ws.py             # per-run event broker + JSONL log
│   ├── run_manager.py    # owns asyncio.Tasks for active agent runs
│   ├── schemas.py        # pydantic DTOs
│   └── routes/           # one router per resource
└── frontend/
    └── index.html        # HTMX + Alpine + Tailwind single-page UI
```

## Hardening checklist (Sprint 11)

- [x] HTTP Basic auth gate (`require_auth` on every router)
- [x] Default-deny when credentials are unconfigured (HTTP 503)
- [x] Rate-limit on `POST /api/sudo/unlock` (5 / 60 s / process)
- [x] CSP / X-Frame-Options / Referrer-Policy / Permissions-Policy headers
- [x] HSTS auto-emitted when proxied over HTTPS
- [x] CLI refuses non-loopback bind without `--cert` / `--key`
- [x] WebSocket explicit auth handshake (no cookie sharing trickery)
- [x] Sudo passwords kept in mlock'd bytearrays, zeroized on lock/expiry,
      never logged or persisted (see `core/sudo_vault.py`)
- [x] Audit log records sudo unlock/lock/failure events without password
- [ ] (future) OIDC / Keycloak in place of HTTP Basic
- [ ] (future) per-route CSRF tokens for state-changing requests
