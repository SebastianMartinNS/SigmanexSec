# SAP-Pentest — Installation guide

This is the long-form installation guide. For a quick refresher see
the *Quick start* section in [README.md](../README.md).

> **⚠️ Authorization is mandatory.** Read
> [AUTHORIZATION.md](../AUTHORIZATION.md) before creating an
> engagement. SAP-Pentest performs *active* security testing and
> refuses to act outside the declared scope, but it is the operator's
> legal responsibility to hold a written authorization from the
> legitimate owner of every target.

---

## 1. Prerequisites

| Component | Requirement |
|---|---|
| OS | Parrot OS 6.x (or any Debian-based distro with `apt` and the Parrot tool repos) |
| Kernel | 6.17 (NVIDIA 550 DKMS is broken on 6.19 — see [`switch_to_kernel617.sh`](../switch_to_kernel617.sh)) |
| GPU | NVIDIA RTX 4060 8 GB or better (CPU-only fallback supported via `NGL=0`) |
| RAM | 16 GB minimum |
| Disk | 30 GB free (10 GB for the GGUF model + ~5 GB for llama.cpp build artefacts + room for engagement data) |
| Python | 3.11 or 3.13 |
| Git | 2.40+ (submodule support) |
| Network | Required for OSINT live tests and model download; optional for offline runs |

---

## 2. Clone the repository

The `llama.cpp/` directory is a **git submodule** pointing at the
upstream repository. The nine local patches are stored separately
under [`patches/llama.cpp/`](../patches/llama.cpp/) and applied by
[`scripts/apply_llamacpp_patches.sh`](../scripts/apply_llamacpp_patches.sh).

```bash
git clone --recursive https://github.com/SigmanexSec/SigmanexSec.git sap-pentest
cd sap-pentest

# If you forgot --recursive:
git submodule update --init --recursive
```

---

## 3. System bootstrap (NVIDIA + Parrot tools)

```bash
bash install_gpu.sh
```

This installs the NVIDIA 550 DKMS driver matched to kernel 6.17, the
CUDA toolkit, and the Parrot offensive tool packages used by the
catalog. Re-run is safe (idempotent).

---

## 4. Build the patched llama.cpp

```bash
# Apply the nine SAP-Pentest patches on top of the pinned upstream commit
bash scripts/apply_llamacpp_patches.sh

# Rebuild the embedded WebUI bundle (it is gzip-compiled into the binary)
cd llama.cpp/tools/server/webui
node node_modules/.bin/vite build
bash scripts/post-build.sh
cd ../../..

# Build llama-server with CUDA
cmake -B build -DGGML_CUDA=ON -DLLAMA_BUILD_SERVER=ON
cmake --build build --config Release -j$(nproc)
cd ..
```

The full inventory of patches and rationale is in
[LLAMACPP_FORK.md](../LLAMACPP_FORK.md).

> **Node.js note.** If your distro lacks Node, the install script can
> link the Node bundled with Playwright:
> ```
> ln -sf ~/.local/lib/python3.13/site-packages/playwright/driver/node ~/.local/bin/node
> ```

---

## 5. Download a GGUF model

GGUF model files are **not** distributed with the repository (they are
multi-gigabyte binaries). Pull a Qwen3.5-class model into
`llama.cpp/models/`:

```bash
mkdir -p llama.cpp/models
# Example — replace with the variant you intend to use
huggingface-cli download <org>/<model> --include "*Q4_K_M*" \
    --local-dir llama.cpp/models --local-dir-use-symlinks False
```

Verify the SHA-256 against [models.sha256](../models.sha256):

```bash
( cd llama.cpp/models && sha256sum -c ../../models.sha256 )
```

The default model name passed to the API is set via `LLM_MODEL` in
`.env` (the llama.cpp server ignores the name, but the agent uses it
in audit metadata).

---

## 6. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# (optional) Install Parrot tools the install_gpu.sh step missed
bash scripts/install_missing_tools.sh
```

---

## 7. Configure credentials and secrets

Copy the example env file and edit it:

```bash
cp .env.example .env
chmod 600 .env
```

The dashboard **refuses to start** without these values and returns
HTTP 503 on every API call until they are provided.

### 7.1 Single-user bootstrap (development)

```ini
SAP_DASHBOARD_USER=admin
SAP_DASHBOARD_PASS=<long random passphrase>
SAP_SESSION_SECRET=<output of: python -c "import secrets; print(secrets.token_urlsafe(48))">
```

The bootstrap user is always treated as `admin`.

### 7.2 Multi-user RBAC (production)

Set `SAP_DASHBOARD_USERS` to a JSON map of `username → {pass, role}`.
Roles: `viewer` (read-only), `operator` (run engagements, request
sudo, drive interactive sessions), `admin` (settings, GDPR purge,
system reset).

```ini
SAP_DASHBOARD_USERS={"alice":{"pass":"…","role":"admin"},"bob":{"pass":"…","role":"operator"},"carol":{"pass":"…","role":"viewer"}}
```

If both blocks are set, the bootstrap user is merged into the
directory (and stays admin).

> **Storage model.** Passwords live in process memory (loaded from
> environment variables) and are compared with
> `secrets.compare_digest`. They are never written to disk by the
> platform. Keep `.env` `chmod 600`, owned by the runtime user, and
> out of version control. The repository ignores `.env` by default.

### 7.3 Session cookie secret

`SAP_SESSION_SECRET` signs the `sap_session` cookie via
`itsdangerous`. If you do not set it, every restart invalidates all
logged-in browser sessions. Generate it once with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 7.4 LLM provider

The default is the local llama.cpp server on port 8080. If you want
to use a hosted model instead, switch `LLM_PROVIDER=anthropic` or
`openai` and provide the relevant API key. See the comments in
[`.env.example`](../.env.example).

---

## 8. Start the platform

```bash
bash start_all.sh
```

This brings up, in order:

1. `sudo_broker` (UNIX socket under `logs/sudo_broker.sock`)
2. `llama-server` on `127.0.0.1:8080`
3. The six MCP servers on ports `9001-9006`
4. The FastAPI dashboard on `127.0.0.1:8765`

Helpers:

- `bash status_all.sh` — show PIDs and health of every component
- `bash monitor_all.sh` — multi-pane log tailer
- `bash stop_all.sh` — shut everything down

---

## 9. First login

Open <http://127.0.0.1:8765> in a browser on the same host and log
in with the `SAP_DASHBOARD_USER` / `SAP_DASHBOARD_PASS` you set in
step 7.

You should land on the engagements page. From there:

- **Create an engagement** — the wizard captures scope (CIDR /
  domain / URL + identity) and the `authorization_ref` (and
  `osint_authorization_ref` for identity OSINT). See
  [AUTHORIZATION.md](../AUTHORIZATION.md).
- **Run the agent** — pick an engagement and choose Planning,
  Execution or Step mode. Step mode pauses before each tool call so
  you can approve or veto it.
- **Sudo unlock** — in the dashboard, *Settings → Sudo*, enter the
  password once. It is stored in `mlock`'d memory in the broker
  daemon and zeroized after the configured TTL. The password never
  reaches the LLM context.

You can also drive the platform from the CLI without a browser:

```bash
python cli.py engage          # interactive engagement wizard
python cli.py list            # list engagements
python cli.py run -e <id> -o "Find all vulnerabilities on 10.0.0.1"
python cli.py status -e <id>
```

---

## 10. Network exposure (optional)

The dashboard handles credentials and triggers privileged actions.
The CLI **refuses to bind a non-loopback host without TLS**:

```bash
python cli.py dashboard --host 0.0.0.0 --port 8765 --cert cert.pem --key key.pem
```

For LAN deployments prefer terminating TLS at a reverse proxy
(Caddy, nginx) and binding the dashboard to `127.0.0.1`.

For container / systemd hardening profiles see
[`deploy/podman/`](../deploy/podman/) and
[`deploy/systemd/`](../deploy/systemd/), validated by
[`scripts/check_hardening.sh`](../scripts/check_hardening.sh).

---

## 11. Verifying the install

```bash
# Run the offline test suite (~25 s, 402 tests).
pytest tests/

# Audit chain integrity check
python -m core.audit_log verify

# systemd unit hardening (if you deployed via the units in deploy/systemd/)
bash scripts/check_hardening.sh
```

Live OSINT and lab end-to-end tests are opt-in; see the *Testing*
section in the [README](../README.md#testing).

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard returns HTTP 503 on every endpoint | `SAP_DASHBOARD_USER` / `SAP_DASHBOARD_PASS` not in env | Set them in `.env` and restart `start_all.sh` |
| All sessions invalidated after restart | `SAP_SESSION_SECRET` not pinned | Set a stable secret in `.env` |
| `llama-server` returns 500 on tool calls | WebUI bundle out of date or patches not applied | Re-run `scripts/apply_llamacpp_patches.sh` and rebuild the WebUI (step 4) |
| `cmake` fails with `nvcc` not found | CUDA toolkit missing | Re-run `install_gpu.sh` |
| `nvidia-smi` empty after kernel update | Kernel ≥ 6.19 with broken NVIDIA 550 DKMS | `bash switch_to_kernel617.sh` |
| `sudo_broker` permission denied | Socket owned by a different UID | Stop with `stop_all.sh`, remove `logs/sudo_broker.sock`, restart |

For security-relevant issues, see [SECURITY.md](../SECURITY.md).
