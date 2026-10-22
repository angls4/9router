# 9Router Rust

9Router Rust is the model gateway and can serve a static Next.js export directly, with no Next.js server process at runtime. `npm run build:rust-static` produces the static export. The migration is in progress: many Next.js API handlers and authentication flows still need Rust equivalents before a Rust-only deployment is complete.

The Rust service currently includes:

- OpenAI-compatible `/v1` proxying with unbuffered SSE streaming
- Native Anthropic request forwarding (`/v1/messages`) and the `/v1/messages/count_tokens` character-based token estimate endpoint
- Basic non-streaming OpenAI Chat Completions ↔ Anthropic Messages conversion
- Provider and model configuration in SQLite
- Dashboard APIs for provider connections/nodes and compatible model lists, settings and proxy checks, password login/session checks and local password reset, public app-version checks, API keys, Codex and Cursor access-token, GitLab PAT, iFlow cookie, Kiro API key, Xiaomi MiMo API-key/session, and Zed session imports, combos and combo presets, the 1,155-entry model catalog, model tests/availability/cooldowns, provider request-header overrides, suggested model catalogs, Kilo free models, pricing overrides, proxy-pool CRUD, translator diagnostics and Rust tracing log streaming, media voice catalogs, and usage analytics
- Model capability sync status and manual refresh at `/api/models/catalog-sync`, with an automatic 24-hour refresh from models.dev
- OAuth and imported access-token accounts in priority-ordered routing, with `x-connection-id` account pinning and refresh-token rotation for Claude, Codex, Gemini CLI, and accounts that store a standard token endpoint in provider settings
- Usage summary/chart/detail endpoints backed by the shared `usageHistory` and `requestDetails` tables; Rust gateway requests append basic usage rows
- Per-connection Claude OAuth and Codex OAuth/access-token quota reads, including model-specific windows; Codex reset-credit details and user-triggered credit redemption are also available
- Local Browser MCP stdio-to-SSE bridge for the fixed `browsermcp` plugin
- Cached, filtered Cowork MCP registry discovery at `/api/cli-tools/cowork-mcp-registry` and public-server tool probing at `/api/cli-tools/cowork-mcp-tools` (remote probes reject private DNS results and pin resolved public addresses)
- Ordered fallback combos with retries on network errors, HTTP 408, 409, 429, and 5xx
- Optional gateway bearer-key authentication
- Recent request log and a browser UI at `/`
- JSON and multipart request forwarding, including model rewriting
- Streaming forwarding for opaque request bodies with `x-9router-model` when routing resolves to one upstream account; JSON and multipart bodies remain buffered for parsing and rewriting
- Static frontend file serving from `NINEROUTER_STATIC_DIR`, including SPA fallback, path traversal protection, cache headers for Next.js assets, and chunked file reads

Run `npm run build:rust-static` to regenerate Rust's 1,155-entry model catalog and generate `out/` as a static export; the script temporarily disables Next.js API routes, middleware, and the Node-only bootstrap during the build, then restores the source files. Static mode sets `output: export`, adds trailing slashes, and omits runtime rewrites. After building, `./start-rust.sh` automatically serves `out/` and the supported same-origin APIs from Rust; set `NINEROUTER_STATIC_DIR` to override the directory. Dynamic provider, media, CLI, and combo pages have static build parameters; custom provider, embedding, and combo details use query IDs. The static build currently exports all 310 pages. Run `npm run build:rust` after the export to compile the updated catalog into the Rust binary.

The migration is not complete. SAML login redirects and callbacks, remaining OAuth/device-code flows, AWS Bedrock credential validation, full catalog/model capability parity, CLI filesystem adapters, authenticated Cowork MCP tool management, proxy-provider deployment, and specialized audio/image/video/search/web-fetch behavior are not yet implemented in Rust, so those features are unavailable in a Rust-only deployment. OIDC login redirects/callbacks and configuration tests, SAML configuration tests and service-provider metadata, read-only Cowork MCP registry discovery, and Cowork MCP public-server tool probing are available. Password reset clears the stored password hash and is restricted to an authenticated request from a loopback connection. Translator console logs expose Rust tracing events through an in-memory buffer, capped at 1,000 lines; logs emitted by a separate Node process are not included. Registry-backed API-key validation now uses build-generated probe metadata for supported providers; provider-node validation supports OpenAI-compatible, Anthropic-compatible, and embedding endpoints. Claude and Cursor combo presets are served from build-generated lists; Cursor's live model catalog is not refreshed at runtime. Batch connection tests are available for models with a Rust test adapter; other providers still report that no adapter is available. Tunnel, Tailscale, Headroom, pxpipe, shutdown, and update controls are intentionally outside this port's scope. In the combined Next.js/Rust build, unsupported per-connection quota providers, accounts with custom proxy settings, and upstream quota errors can fall back to the existing Node handler; the standalone Rust service returns a marked `501` for those cases. The current cross-protocol converter handles basic non-streaming chat/messages text and tool calls; streaming conversion, image/audio blocks, and provider-specific protocol variants are not complete. Rust's usage rows currently record request counts and latency, not upstream token usage or cost. Credentials are stored in the shared SQLite database, so protect its data directory.

## Run locally

Install Rust with rustup, then from the repository root:

```sh
cargo run --release --manifest-path rust/Cargo.toml
```

Or use `./start-rust.sh`. The service binds to `127.0.0.1:20127`. The first build downloads Rust dependencies. Set these environment variables as needed:

To keep Node as the dashboard frontend and route supported APIs and inference requests through its streaming proxy to Rust, build with `npm run build:rust-frontend`, then run `./start-full.sh`. The build routes `/v1`, `/api/v1`, `/responses`, `/codex`, `/systemone`, supported usage APIs, proxy-pool CRUD, selected translator diagnostics, and supported media voice catalogs through Rust. `start-full.sh` starts Node on port 20127 and Rust on port 20128. Set `NINEROUTER_RUST_URL` if Rust listens elsewhere. Specialized integrations still use Node.

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Listen address |
| `PORT` | `20127` | Listen port |
| `DATA_DIR` | `~/.9router` | SQLite database and runtime data directory |
| `NINEROUTER_STATIC_DIR` | unset | Optional directory containing the static frontend export |
| `NINEROUTER_API_KEY` | unset | Require a bearer key on `/v1/*` and `/admin/*` |
| `MODEL_CATALOG_SYNC` | enabled | Set to `off` to disable scheduled models.dev updates |
| `RUST_LOG` | `info` | Log filter |

Without `NINEROUTER_API_KEY`, the service is unauthenticated. Keep it bound to loopback unless you configure authentication and network access controls.

## Configure

Open `http://127.0.0.1:20127/`. Add a provider with its API base URL, upstream key, protocol, and model names. The UI does not expose saved upstream keys. When editing, leave the key field blank to preserve the stored key.

You can also create a provider over HTTP:

```sh
curl -X PUT http://127.0.0.1:20127/admin/providers \
  -H 'Content-Type: application/json' \
  -d '{"id":"openai","name":"OpenAI","baseUrl":"https://api.openai.com/v1","apiKey":"sk-...","models":["gpt-4.1-mini"]}'
```

Call it using `provider-id/model-name`:

```sh
curl http://127.0.0.1:20127/v1/chat/completions \
  -H 'Authorization: Bearer local-client-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"openai/gpt-4.1-mini","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

If `NINEROUTER_API_KEY` is set, use that same value in the client Authorization header and the page's gateway-key field. Set it for management requests too.

Choose `"apiFormat":"anthropic"` for an Anthropic upstream. The gateway sets `x-api-key` and a default `anthropic-version` header. Native `/v1/messages` requests are forwarded; basic non-streaming OpenAI chat requests are converted to Messages and back. Use native protocol requests for streaming and media content.

## Fallback combos

Combos are ordered lists of `provider/model` targets. The gateway tries the next target on network errors or retryable upstream statuses. Configure them in the UI or with:

```sh
curl -X PUT http://127.0.0.1:20127/admin/combos \
  -H 'Content-Type: application/json' \
  -d '{"name":"balanced","models":["openai/gpt-4.1-mini","backup/fast-model"]}'
```

Then send `"model":"balanced"` in the request. The gateway preserves the incoming API path and query string, forwards JSON or multipart bodies, replaces the model with each selected upstream model, and streams the chosen upstream response to the client.

## Endpoints

- `GET /` — local provider, combo, and request-log UI
- `GET /health`
- `GET /v1/models`
- `ANY /v1/{path}` — upstream API gateway
- `GET /admin/providers`, `PUT /admin/providers`, `DELETE /admin/providers/{id}`
- `GET /admin/combos`, `PUT /admin/combos`, `DELETE /admin/combos/{id}`
- `GET /admin/requests` — most recent 50 requests

## Docker

```sh
docker compose -f docker-compose.rust.yml up --build
```

Set `NINEROUTER_API_KEY` in the environment before exposing the container beyond a trusted local network. Persistent service data is stored in the `9router-rust-data` volume.
