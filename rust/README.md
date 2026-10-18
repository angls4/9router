# 9Router Rust

9Router Rust is a Rust model gateway with a built-in local management page. The existing Node/Next.js app can remain the frontend and route `/v1` traffic to Rust. It has no Headroom integration.

The Rust service includes:

- OpenAI-compatible `/v1` proxying with unbuffered SSE streaming
- Native Anthropic request forwarding (`/v1/messages`)
- Provider and model configuration in SQLite
- Ordered fallback combos with retries on network errors, HTTP 408, 409, 429, and 5xx
- Optional gateway bearer-key authentication
- Recent request log and a browser UI at `/`
- JSON and multipart request forwarding, including model rewriting

The existing Node/Next.js app remains the frontend and continues to serve its dashboard. Rust opens its existing `DATA_DIR/db/data.sqlite` database, so the two processes share provider connections, custom provider nodes, combos, and API keys. Provider OAuth refresh, account pool selection, cross-protocol/media/CLI integrations, and restricted-key allow lists are still being ported; do not send those workloads to Rust until the required behavior is implemented. OpenAI-style clients need OpenAI-compatible upstreams; Anthropic clients use the native Messages API. Credentials are stored in the shared SQLite database, so protect its data directory.

## Run locally

Install Rust with rustup, then from the repository root:

```sh
cargo run --release --manifest-path rust/Cargo.toml
```

Or use `./start-rust.sh`. The service binds to `127.0.0.1:20127`. The first build downloads Rust dependencies. Set these environment variables as needed:

To keep Node as the dashboard frontend and route inference requests through its streaming proxy to Rust, build with `npm run build:rust-frontend`, then run `./start-full.sh`. The build routes `/v1`, `/api/v1`, `/responses`, `/codex`, and `/systemone` through Node to Rust; Node continues to handle dashboard APIs and pages. `start-full.sh` starts Node on port 20127 and Rust on port 20128. Set `NINEROUTER_RUST_URL` if Rust listens elsewhere. Since the full provider/translator port is still in progress, enable this build only when Rust supports the client traffic you intend to send.

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

Choose `"apiFormat":"anthropic"` for an Anthropic upstream. The gateway sets `x-api-key` and a default `anthropic-version` header. Use the client's native `/v1/messages` endpoint and payload; no format translation is performed.

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
