# Bundled `llama.cpp` Fork — Modifications & Build Instructions

> **You must build the vendored fork**, not upstream `llama.cpp`.
> SAP-Pentest depends on a set of nine local patches that are not yet
> merged upstream. Pulling stock `ggerganov/llama.cpp` will break tool
> calling, the WebUI MCP integration, and the CORS proxy.

The fork lives under [`llama.cpp/`](llama.cpp/) inside the repository
and tracks `https://github.com/ggerganov/llama.cpp` at commit
`0beb8db` (`ggml-vulkan: add SGN operator …`) at the time of writing.
Run `git -C llama.cpp log --oneline -1` to confirm the base commit.

This document lists every modified file, what was changed and why,
and whether the patch must be re-applied after pulling upstream.
Run `git -C llama.cpp diff --stat` to verify the same set is dirty
on your checkout.

---

## Build steps

```bash
# 1. Fresh clone (the submodule URL is in .gitmodules)
git clone https://github.com/SebastianMartinNS/SigmanexSec.git sap-pentest
cd sap-pentest

# 2. Pull the upstream llama.cpp tree at the pinned commit
git submodule update --init --recursive

# 3. Apply the nine local patches
bash scripts/apply_llamacpp_patches.sh

# 4. Rebuild the WebUI assets (they are embedded as gzip into the server binary)
cd llama.cpp/tools/server/webui
# Node.js: SAP uses the Node bundled with Playwright when system Node is absent.
#   ln -sf ~/.local/lib/python3.13/site-packages/playwright/driver/node ~/.local/bin/node
node node_modules/.bin/vite build
bash scripts/post-build.sh        # writes index.html.gz.hpp
cd ../../..

# 5. Build llama-server with CUDA (RTX 4060 8 GB target)
cmake -B build -DGGML_CUDA=ON -DLLAMA_BUILD_SERVER=ON
cmake --build build --config Release -j$(nproc)
cd ..

# 6. From the repo root, start the full stack
NGL=12 CTX=32768 bash start_llm.sh server   # uses the patched binary
bash start_all.sh                           # LLM + 6 MCP servers + dashboard
```

If you see `MCP error -32001: Request timed out` in the WebUI, your
build is missing the `mcp_http_runner.py` JSON-mode patch (file 8) or
the WebUI was rebuilt from upstream sources without files 3, 4, 5.

---

## File-by-file changelog

The modifications are grouped by subsystem. Re-apply column says whether
you need to redo the patch after `git pull` from upstream.

### 1. `llama.cpp/common/chat.cpp` — promote `<tool_call>` from reasoning channel

| | |
|---|---|
| **Lines changed** | +77 |
| **Re-apply after pull** | YES — critical for thinking-native models |

Adds two static helpers (`promote_tool_calls_from_field`,
`promote_tool_calls_from_reasoning`) called at the end of
`common_chat_peg_parse`. They scan `msg.reasoning_content` and
`msg.content` for `<tool_call>{…json…}</tool_call>` blocks, parse the
JSON payload, and append it to `msg.tool_calls`.

Without this, Qwen3-class models that emit tool calls inside their
`<think>…</think>` span have those calls swallowed by the reasoning
parser, and the agent loop deadlocks waiting for an action.

### 2. `llama.cpp/tools/server/server-cors-proxy.h` — host:port + HTTPS short-circuit

| | |
|---|---|
| **Lines changed** | +33 / −2 |
| **Re-apply after pull** | YES — required for any non-port-80/443 MCP target |

Two related fixes in `proxy_request`:

* **Host:port split.** Upstream `proxy_request` passes the scheme
  default port (80/443) to the cpp-httplib client and ignores any port
  embedded in `parsed_url.host` such as `127.0.0.1:9001`. The patch
  splits `host:port` (handling IPv6 brackets `[::1]:9001`) so that the
  WebUI's `Use CORS proxy` flag actually reaches the SAP MCP servers
  on ports 9001-9006. Without it the proxy returns
  `proxy error: Could not establish connection`.
* **HTTPS no-OpenSSL short-circuit.** When `CPPHTTPLIB_OPENSSL_SUPPORT`
  is undefined the upstream code throws HTTP 500 for every HTTPS
  request. The patch returns HTTP 204 instead, so the WebUI's
  external-favicon fetch (Google service) does not flood the console.

### 3. `llama.cpp/tools/server/webui/src/lib/utils/favicon.ts` — non-routable host filter

| | |
|---|---|
| **Lines changed** | +25 |
| **Re-apply after pull** | YES — pairs with patch 2 |

`getFaviconUrl` now returns `null` for IPv4 literals, IPv6 literals,
`localhost`, and single-label hostnames. Upstream sliced `127.0.0.1` to
`domain=0.1` and re-fetched in a tight loop, producing a console-spam
storm when the CORS proxy could not satisfy the upstream request.

### 4. `llama.cpp/tools/server/webui/src/lib/stores/settings.svelte.ts` — auto-migrate localStorage

| | |
|---|---|
| **Lines changed** | +33 |
| **Re-apply after pull** | YES — performance + UX |

`loadConfig` now detects two legacy states in `localStorage`
(`mcpServers === '[]'`, or any entry with `useProxy:true` targeting
`127.0.0.1:900X`) and rewrites them to the new SAP defaults
(`useProxy:false`, all six servers enabled). Without this migration
existing browsers keep routing all SAP MCP traffic through
`/cors-proxy` on port 8080, exhausting Chrome's six-connections-per-
origin limit on the SSE streams and freezing chat in
`processing…`.

### 5. `llama.cpp/tools/server/webui/src/lib/stores/mcp.svelte.ts` — enable-by-default override

| | |
|---|---|
| **Lines changed** | +4 / −1 |
| **Re-apply after pull** | YES — pairs with patch 4 and 6 |

`getEnabledServers` now treats `override?.enabled ?? true`. Combined
with patch 6 this makes the six SAP MCP servers come up enabled on
first load.

### 6. `llama.cpp/tools/server/webui/src/lib/constants/settings-config.ts` — ship SAP MCP defaults

| | |
|---|---|
| **Lines changed** | +9 / −1 |
| **Re-apply after pull** | YES — onboarding |

`SETTING_CONFIG_DEFAULT.mcpServers` is now pre-populated with the six
SAP MCP servers (`sap-engagement` 9001, `sap-recon` 9002,
`sap-exploit` 9003, `sap-blueteam` 9004, `sap-parrot` 9005,
`sap-osint` 9006), each with `enabled:true, useProxy:false`. Users
get a working configuration without editing JSON by hand.

### 7. `llama.cpp/tools/server/webui/src/lib/services/mcp.service.ts` — protocol layer hardening

| | |
|---|---|
| **Lines changed** | +19 / −5 |
| **Re-apply after pull** | YES — required for the streamable-HTTP transport in JSON mode |

Tightens the streamable-HTTP transport to honour `Mcp-Session-Id` and
`Mcp-Protocol-Version` headers, treats HTTP 404 on `/mcp` as a
"session expired, re-initialize" signal (paired with patch 8), and
disables the SSE auto-reconnect loop when the server already replied
in JSON mode.

### 8. `llama.cpp/tools/server/webui/src/lib/constants/mcp.ts` and `types/mcp.d.ts` — protocol constants & typings

| | |
|---|---|
| **Lines changed** | +1 / −1 (constants), +2 (types) |
| **Re-apply after pull** | MAYBE — small surface, may be merged upstream |

`PROTOCOL_VERSION` bumped to the version SAP MCP servers negotiate;
the `MCPClientConfig` type gained two optional fields
(`useProxy?: boolean`, `enabled?: boolean`) referenced by patches 4–6.

### 9. `llama.cpp/tools/server/public/index.html.gz` — rebuilt asset

| | |
|---|---|
| **Lines changed** | binary regen |
| **Re-apply after pull** | AUTOMATIC if you re-run the WebUI build step |

The compressed WebUI bundle ships embedded into `llama-server`. Any
change to the four `.svelte.ts` / `.ts` files above requires
re-running step 3 of the build. A `git diff` on the binary just
indicates the asset is in sync with the patched sources.

---

## Companion files outside `llama.cpp/`

The following Sigmanex files live at the repository root and orchestrate
the patched server. They are not part of upstream but are mentioned
here because they pair with the `llama.cpp/` patches above.

### `mcp_http_runner.py` — JSON-RPC over POST + session-404 rewrite

Sets `mcp.settings.json_response = True` *before* calling
`mcp.streamable_http_app()`. The default SSE response mode races with
the WebUI reconnect cycle (POST `/mcp` accepted, response sent on a
GET `/mcp` SSE stream the client may not have re-opened) and produces
`MCP error -32001: Request timed out` after 60 s. JSON mode delivers
the JSON-RPC reply on the POST itself: 12-26 ms per server.

The runner also installs a permissive `CORSMiddleware`
(`allow_origins=["*"]`, `expose_headers=["Mcp-Session-Id",
"Mcp-Protocol-Version"]`) and wraps the FastAPI app with a 400→404
rewrite so that the WebUI auto-reinitializes the session instead of
hanging when the in-memory session is reaped.

### `start_mcp_http.sh` — spawn all six MCP servers

Spawns the six SAP MCP servers in parallel over HTTP (ports
9001-9006). Verify with `ss -tlnp | grep ':900[1-6]'` → six
listeners. The osint server (9006) was added in the v2.1 release;
re-check the `SERVERS` array if you forked an older copy.

### `start_llm.sh` — patched-binary launcher

Launches the local llama-server with the chat template that overrides
the xLAM template embedded in the Qwen3.5-35B-A3B-heretic GGUF
(otherwise multi-step tool calls fail with HTTP 500
`parse error at line 1, column 58`). Auto-detects NGL based on free
VRAM, conservatively forcing `--no-kv-offload` when
`NGL>0 && CTX>32768` to keep the KV cache in RAM and avoid CUDA OOM
on the RTX 4060 8 GB reference platform.

The active exec block is around line 154; if you customize, remember
to keep `--chat-template-file "$QWEN3_TMPL"` on both exec paths.

### `launch_sap.sh` — single-entry-point

Exports the canonical environment (`NGL=12`, `CTX=32768`,
`VRAM_HEADROOM_MB=3500`) before invoking `start_all.sh`. Use this
unless you have a clear reason to override.

---

## Why these patches stay local

* **Tool-call promotion (file 1)** is a Qwen-specific workaround.
  Upstream is converging toward a generic `--reasoning-format` flag;
  when it lands, this patch can be dropped.
* **CORS proxy host:port (file 2)** is a clear upstream bug; PR is
  pending review in `ggerganov/llama.cpp`.
* **WebUI MCP defaults (files 4-6, 8, 9)** are SAP-specific brand
  configuration and will not be upstreamed.
* **HTTPS short-circuit (file 2) and favicon filter (file 3)** are
  defence-in-depth against console spam in builds without OpenSSL;
  upstream may prefer to require OpenSSL instead.

If you push patches upstream please coordinate via the issue tracker
so this document and `start_llm.sh` can be updated.

---

## Verifying a clean install

```bash
# 1. All nine files dirty?
git -C llama.cpp diff --stat | wc -l        # → 10 (9 files + total line)

# 2. Server binary built with CUDA?
llama.cpp/build/bin/llama-server --version | grep -i cuda

# 3. WebUI bundle rebuilt?
ls -lh llama.cpp/tools/server/public/index.html.gz

# 4. MCP HTTP runner using JSON mode?
grep -n 'json_response = True' mcp_http_runner.py

# 5. End-to-end: 9/9 services UP?
bash status_all.sh
```

A green run of `bash status_all.sh` plus a successful tool call from
the WebUI confirms that every patch in this document is in effect.
