# 9Router Rust

9Router Rust is a Rust model gateway with a built-in local management page. The existing Node/Next.js app can remain the frontend and route `/v1` traffic to Rust. It has no Headroom integration.

The Rust service currently includes:

- OpenAI-compatible `/v1` proxying with unbuffered SSE streaming
- Native Anthropic request forwarding (`/v1/messages`)
- Basic non-streaming OpenAI Chat Completions ↔ Anthropic Messages conversion
- Provider and model configuration in SQLite
- Dashboard APIs for provider connections/nodes, settings, API keys, combos, model aliases/custom/disabled models, pricing overrides, proxy-pool CRUD, translator diagnostics, media voice catalogs, and usage analytics
- OAuth and imported access-token accounts in priority-ordered routing, with `x-connection-id` account pinning and refresh-token rotation for Claude, Codex, Gemini CLI, and accounts that store a standard token endpoint in provider settings
- Usage summary/chart/detail endpoints backed by the shared `usageHistory` and `requestDetails` tables; Rust gateway requests append basic usage rows
- Local Browser MCP stdio-to-SSE bridge for the fixed `browsermcp` plugin
- Ordered fallback combos with retries on network errors, HTTP 408, 409, 429, and 5xx
- Optional gateway bearer-key authentication
- Recent request log and a browser UI at `/`
- JSON and multipart request forwarding, including model rewriting

The existing Node/Next.js app remains the frontend and shares its existing `DATA_DIR/db/data.sqlite` database with Rust. The Rust build routes the supported dashboard data APIs through Rust. Headroom controls are hidden in the Rust frontend build and its settings are omitted from Rust responses. OAuth login/import flows, providers with custom OAuth or inference protocols, CLI filesystem adapters, Cowork MCP registry/tool management, tunnel lifecycle management, proxy-provider deployment, translator console log APIs, media voice catalogs outside Deepgram/ElevenLabs/Inworld/MiniMax, and provider quota/reset APIs still run in Node. The current cross-protocol converter handles basic non-streaming chat/messages text and tool calls; streaming conversion, image/audio blocks, and provider-specific protocol variants are not complete. Rust's usage rows currently record request counts and latency, not upstream token usage or cost. Credentials are stored in the shared SQLite database, so protect its data directory.

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
| `DATA_DIR` | `~/.9router` | SQLite database directory |
| `NINEROUTER_API_KEY` | unset | Require a bearer key on `/v1/*` and `/admin/*` |
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
