use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{
        Html, IntoResponse, Redirect, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{any, get},
};
use base64::Engine;
use bytes::Bytes;
use chrono::Timelike;
use futures_util::StreamExt;
use hmac::Mac;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::{
    auth,
    console_logs::{ConsoleLogBuffer, ConsoleLogEvent},
    store::{self, ComboInput, Provider, ProviderInput},
};

struct UsageCacheEntry {
    value: Value,
    expires_at: Instant,
}

const MAX_PROXY_BODY_BYTES: usize = 50 * 1024 * 1024;

static USAGE_CACHE: OnceLock<tokio::sync::Mutex<HashMap<String, UsageCacheEntry>>> =
    OnceLock::new();
static KILO_MODELS_CACHE: OnceLock<tokio::sync::Mutex<Option<(Instant, Value)>>> = OnceLock::new();
static CATALOG_SYNC_STATE: OnceLock<tokio::sync::Mutex<CatalogSyncState>> = OnceLock::new();
static VERSION_CACHE: OnceLock<tokio::sync::Mutex<Option<(Instant, Option<String>)>>> =
    OnceLock::new();
static COWORK_MCP_REGISTRY_CACHE: OnceLock<tokio::sync::Mutex<Option<(Instant, Value)>>> =
    OnceLock::new();

#[derive(Default)]
struct CatalogSyncState {
    running: bool,
    last_sync: Option<i64>,
    last_error: Option<String>,
    last_result: Option<Value>,
    etag: Option<String>,
    file_version: Option<u64>,
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub http: reqwest::Client,
    pub api_key: Option<String>,
    pub auth_secret: Arc<Vec<u8>>,
    pub login_attempts: Arc<tokio::sync::Mutex<HashMap<String, LoginAttempt>>>,
    pub oauth_locks: Arc<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    pub mcp_entries: Arc<tokio::sync::Mutex<HashMap<String, McpEntry>>>,
    pub console_logs: ConsoleLogBuffer,
}

#[derive(Clone)]
pub(crate) struct LoginAttempt {
    failures: u32,
    lock_level: usize,
    last_failure: Instant,
    locked_until: Option<Instant>,
}

#[derive(Clone)]
pub(crate) struct McpEntry {
    child: Arc<tokio::sync::Mutex<tokio::process::Child>>,
    stdin: Arc<tokio::sync::Mutex<tokio::process::ChildStdin>>,
    messages: tokio::sync::broadcast::Sender<String>,
    sessions: Arc<AtomicUsize>,
}

struct McpSessionGuard {
    state: AppState,
    plugin: String,
    sessions: Arc<AtomicUsize>,
    child: Arc<tokio::sync::Mutex<tokio::process::Child>>,
}

impl Drop for McpSessionGuard {
    fn drop(&mut self) {
        let state = self.state.clone();
        let plugin = self.plugin.clone();
        let sessions = self.sessions.clone();
        let child = self.child.clone();
        let cleanup = async move {
            let removed = {
                let mut entries = state.mcp_entries.lock().await;
                let last_session = sessions.fetch_sub(1, Ordering::AcqRel) <= 1;
                last_session
                    && entries
                        .get(&plugin)
                        .is_some_and(|current| Arc::ptr_eq(&current.sessions, &sessions))
                    && entries.remove(&plugin).is_some()
            };
            if removed {
                let mut child = child.lock().await;
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(cleanup);
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route(
            "/health",
            get(|| async { Json(json!({"status":"ok","service":"9router-rust"})) }),
        )
        .route(
            "/api/health",
            get(|| async { Json(json!({"status":"ok","service":"9router-rust"})) }),
        )
        .route(
            "/api/init",
            get(|| async { (StatusCode::OK, "Initialized") }),
        )
        .route("/api/locale", axum::routing::post(api_set_locale))
        .route("/api/tags", get(api_tags).options(api_tags_options))
        .route("/api/settings/require-login", get(api_require_login_status))
        .route(
            "/api/settings/database",
            get(api_export_database).post(api_import_database),
        )
        .route(
            "/api/settings/proxy-test",
            axum::routing::post(api_proxy_test),
        )
        .route("/api/auth/status", get(api_auth_status))
        .route("/api/auth/login", axum::routing::post(api_auth_login))
        .route("/api/auth/logout", axum::routing::post(api_auth_logout))
        .route(
            "/api/auth/reset-password",
            axum::routing::post(api_auth_reset_password),
        )
        .route(
            "/api/auth/oidc/test",
            axum::routing::post(api_auth_oidc_test),
        )
        .route("/api/auth/oidc/start", get(api_auth_oidc_start))
        .route("/api/auth/oidc/callback", get(api_auth_oidc_callback))
        .route(
            "/api/auth/saml/test",
            axum::routing::post(api_auth_saml_test),
        )
        .route("/api/auth/saml/metadata", get(api_auth_saml_metadata))
        .route("/api/version", get(api_version))
        .route(
            "/api/oauth/codex/import-token",
            axum::routing::post(api_import_codex_token),
        )
        .route(
            "/api/oauth/gitlab/pat",
            axum::routing::post(api_import_gitlab_pat),
        )
        .route(
            "/api/oauth/iflow/cookie",
            axum::routing::post(api_import_iflow_cookie),
        )
        .route(
            "/api/oauth/xiaomi-mimo/api-key",
            axum::routing::post(api_import_xiaomi_mimo_key),
        )
        .route(
            "/api/oauth/zed/import",
            axum::routing::post(api_import_zed_token),
        )
        .route(
            "/api/oauth/cursor/import",
            get(api_cursor_import_instructions).post(api_import_cursor_token),
        )
        .route(
            "/api/oauth/kiro/api-key",
            axum::routing::post(api_import_kiro_api_key),
        )
        .route("/admin/providers", get(list_providers).put(save_provider))
        .route("/api/providers/client", get(api_models))
        .route(
            "/api/providers/validate",
            axum::routing::post(api_validate_provider_key),
        )
        .route("/api/providers/suggested-models", get(api_suggested_models))
        .route("/api/providers/kilo/free-models", get(api_kilo_free_models))
        .route(
            "/api/providers/test-batch",
            axum::routing::post(api_test_provider_batch),
        )
        .route(
            "/api/providers",
            get(api_list_connections).post(api_create_connection),
        )
        .route(
            "/api/providers/{id}",
            get(api_get_connection)
                .put(api_update_connection)
                .delete(api_delete_connection),
        )
        .route(
            "/api/providers/{id}/overrides",
            get(api_get_provider_overrides).put(api_put_provider_overrides),
        )
        .route("/api/providers/{id}/models", get(api_get_provider_models))
        .route(
            "/api/providers/{id}/test",
            axum::routing::post(api_test_provider_connection),
        )
        .route(
            "/api/providers/{id}/test-models",
            axum::routing::post(api_test_provider_models),
        )
        .route(
            "/api/provider-nodes",
            get(api_list_provider_nodes).post(api_create_provider_node),
        )
        .route(
            "/api/provider-nodes/{id}",
            axum::routing::put(api_update_provider_node).delete(api_delete_provider_node),
        )
        .route(
            "/api/provider-nodes/validate",
            axum::routing::post(api_validate_provider_node),
        )
        .route(
            "/api/models",
            get(api_dashboard_models).put(set_dashboard_model_alias),
        )
        .route(
            "/api/models/availability",
            get(api_model_availability).post(api_clear_model_cooldown),
        )
        .route(
            "/api/models/catalog-sync",
            get(api_catalog_sync_status).post(api_catalog_sync_now),
        )
        .route("/api/models/test", axum::routing::post(api_test_model))
        .route("/api/combos", get(api_list_combos).post(api_create_combo))
        .route(
            "/api/combos/presets",
            get(api_combo_presets_get).post(api_combo_presets_post),
        )
        .route(
            "/api/combos/{id}",
            get(api_get_combo)
                .put(api_update_combo)
                .delete(api_delete_combo),
        )
        .route(
            "/api/models/alias",
            get(model_aliases)
                .put(set_model_alias)
                .delete(delete_model_alias),
        )
        .route(
            "/api/models/custom",
            get(custom_models)
                .post(add_custom_model)
                .delete(delete_custom_model),
        )
        .route(
            "/api/models/disabled",
            get(disabled_models)
                .post(disable_models)
                .delete(enable_models),
        )
        .route("/api/keys", get(api_list_keys).post(api_create_key))
        .route(
            "/api/keys/{id}",
            get(api_get_key).put(api_update_key).delete(api_delete_key),
        )
        .route(
            "/api/settings",
            get(api_get_settings).patch(api_patch_settings),
        )
        .route(
            "/api/pricing",
            get(api_get_pricing)
                .patch(api_patch_pricing)
                .delete(api_delete_pricing),
        )
        .route("/api/usage/logs", get(api_usage_logs))
        .route("/api/usage/request-logs", get(api_usage_logs))
        .route(
            "/api/usage/{connection_id}/codex-reset-credits",
            get(api_codex_reset_credits).post(api_consume_codex_reset_credit),
        )
        .route("/api/usage/{connection_id}", get(api_connection_usage))
        .route("/api/usage/history", get(api_usage_stats))
        .route("/api/usage/stats", get(api_usage_stats))
        .route("/api/usage/chart", get(api_usage_chart))
        .route("/api/usage/providers", get(api_usage_providers))
        .route("/api/usage/request-details", get(api_usage_details))
        .route("/api/usage/stream", get(api_usage_stream))
        .route(
            "/api/proxy-pools",
            get(api_list_proxy_pools).post(api_create_proxy_pool),
        )
        .route(
            "/api/proxy-pools/{id}",
            get(api_get_proxy_pool)
                .put(api_update_proxy_pool)
                .delete(api_delete_proxy_pool),
        )
        .route(
            "/api/proxy-pools/{id}/test",
            axum::routing::post(api_test_proxy_pool),
        )
        .route("/api/translator/load", get(api_translator_load))
        .route(
            "/api/translator/save",
            axum::routing::post(api_translator_save),
        )
        .route(
            "/api/translator/translate",
            axum::routing::post(api_translator_translate),
        )
        .route(
            "/api/translator/send",
            axum::routing::post(api_translator_send),
        )
        .route(
            "/api/translator/console-logs",
            get(api_translator_console_logs).delete(api_translator_clear_console_logs),
        )
        .route(
            "/api/translator/console-logs/stream",
            get(api_translator_console_log_stream),
        )
        .route(
            "/api/media-providers/tts/{provider}/voices",
            get(api_media_tts_voices),
        )
        .route(
            "/api/media-providers/tts/voices",
            get(api_tts_voices).options(api_tts_voices_options),
        )
        .route(
            "/v1/audio/voices",
            get(api_v1_audio_voices).options(api_tts_voices_options),
        )
        .route(
            "/api/v1/audio/voices",
            get(api_v1_audio_voices).options(api_tts_voices_options),
        )
        .route("/api/mcp/{plugin}/sse", get(api_mcp_sse))
        .route(
            "/api/mcp/{plugin}/message",
            axum::routing::post(api_mcp_message),
        )
        .route(
            "/api/cli-tools/cowork-mcp-registry",
            get(api_cowork_mcp_registry),
        )
        .route(
            "/api/cli-tools/cowork-mcp-tools",
            axum::routing::post(api_cowork_mcp_tools),
        )
        .route(
            "/admin/providers/{id}",
            axum::routing::delete(remove_provider),
        )
        .route("/admin/combos", get(list_combos).put(save_combo))
        .route("/admin/combos/{id}", axum::routing::delete(remove_combo))
        .route("/admin/requests", get(list_requests))
        .route("/v1/models", get(list_models))
        .route("/api/v1/models", get(list_models))
        .route(
            "/v1/messages/count_tokens",
            axum::routing::post(api_count_anthropic_tokens)
                .options(api_count_anthropic_tokens_options),
        )
        .route(
            "/api/v1/messages/count_tokens",
            axum::routing::post(api_count_anthropic_tokens)
                .options(api_count_anthropic_tokens_options),
        )
        .route("/v1", any(proxy_root))
        .route("/api/v1", any(proxy_root))
        .route("/api/v1/{*path}", any(proxy))
        .route("/v1/{*path}", any(proxy))
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            protect_dashboard_api,
        ))
        .fallback(static_fallback)
        .with_state(state)
}

async fn protect_dashboard_api(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !path.starts_with("/api/")
        || path == "/api/health"
        || path.starts_with("/api/v1/")
        || path == "/api/v1"
        || path.starts_with("/api/v1beta/")
        || path == "/api/v1beta"
    {
        return next.run(request).await;
    }

    let always_protected = [
        "/api/settings/database",
        "/api/version/shutdown",
        "/api/version/update",
    ]
    .iter()
    .any(|protected| path == *protected || path.starts_with(&format!("{protected}/")));
    if !always_protected
        && [
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/status",
            "/api/auth/oidc/start",
            "/api/auth/oidc/callback",
            "/api/auth/saml/metadata",
            "/api/init",
            "/api/locale",
            "/api/version",
            "/api/settings/require-login",
        ]
        .iter()
        .any(|public| path == *public)
    {
        return next.run(request).await;
    }

    let settings = read_settings(&state.db).await.unwrap_or_else(|_| json!({}));
    let session_valid = dashboard_session(&state, request.headers()).is_some();
    let login_disabled = settings["requireLogin"] == false;
    if path == "/api/auth/reset-password"
        && (!is_loopback_request(&request) || (!session_valid && !login_disabled))
    {
        return ApiError::new(StatusCode::FORBIDDEN, "Local authenticated access required")
            .into_response();
    }
    let supplied_key = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|h| h.to_str().ok())
        });
    let internal_key_valid = state
        .api_key
        .as_deref()
        .is_some_and(|key| Some(key) == supplied_key);
    if (always_protected && !session_valid)
        || (!always_protected && !login_disabled && !session_valid && !internal_key_valid)
    {
        return ApiError::unauthorized("Unauthorized").into_response();
    }

    // API key protection is for direct gateway access. A dashboard session is
    // the browser credential, so pass the configured internal key only after
    // that session (or requireLogin=false) has been accepted.
    if !always_protected && (session_valid || login_disabled) {
        if let Some(key) = state.api_key.as_deref() {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {key}")) {
                request.headers_mut().insert(header::AUTHORIZATION, value);
            }
        }
    }
    next.run(request).await
}

fn is_loopback_request(request: &axum::extract::Request) -> bool {
    if request.headers().contains_key("x-9r-via-proxy") {
        return false;
    }
    let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() else {
        return false;
    };
    if !is_loopback_ip(peer.ip()) {
        return false;
    }
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        let Ok(origin) = origin.to_str() else {
            return false;
        };
        let Ok(origin) = reqwest::Url::parse(origin) else {
            return false;
        };
        let Some(host) = origin.host_str() else {
            return false;
        };
        if host != "localhost" && !host.parse::<std::net::IpAddr>().is_ok_and(is_loopback_ip) {
            return false;
        }
    }
    true
}

fn is_loopback_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_loopback(),
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
    }
}

async fn api_auth_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => {
            return no_store_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"Unable to read settings"}),
            );
        }
    };
    let session = dashboard_session(&state, &headers);
    let require_login = settings["requireLogin"] != false;
    let auth_mode = settings["authMode"].as_str().unwrap_or("password");
    let sso_type = settings["ssoType"].as_str().unwrap_or("oidc");
    let oidc_configured = ["oidcIssuerUrl", "oidcClientId", "oidcClientSecret"]
        .iter()
        .all(|key| {
            settings[*key]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        });
    let saml_configured = ["samlEntryPoint", "samlIssuer", "samlCert"]
        .iter()
        .all(|key| {
            settings[*key]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        });
    let oidc_name = session
        .as_ref()
        .and_then(|payload| payload["oidcName"].as_str())
        .unwrap_or_default();
    let oidc_email = session
        .as_ref()
        .and_then(|payload| payload["oidcEmail"].as_str())
        .unwrap_or_default();
    let saml_name = session
        .as_ref()
        .and_then(|payload| payload["samlName"].as_str())
        .unwrap_or_default();
    let saml_email = session
        .as_ref()
        .and_then(|payload| payload["samlEmail"].as_str())
        .unwrap_or_default();
    let is_saml = session
        .as_ref()
        .is_some_and(|payload| payload["saml"] == true);
    let is_oidc = session
        .as_ref()
        .is_some_and(|payload| payload["oidc"] == true);
    let display_name = if !saml_name.is_empty() {
        saml_name
    } else if !saml_email.is_empty() {
        saml_email
    } else if !oidc_name.is_empty() {
        oidc_name
    } else if !oidc_email.is_empty() {
        oidc_email
    } else if is_saml {
        "SAML user"
    } else if is_oidc {
        "OIDC user"
    } else {
        "Password user"
    };
    let login_method = if is_saml {
        "SAML"
    } else if is_oidc {
        "OIDC"
    } else {
        "Password"
    };
    no_store_json(
        StatusCode::OK,
        json!({
            "requireLogin":require_login,
            "authMode":auth_mode,
            "ssoType":sso_type,
            "oidcConfigured":oidc_configured,
            "oidcLoginLabel":settings["oidcLoginLabel"].as_str().filter(|v| !v.trim().is_empty()).unwrap_or("Sign in with OIDC"),
            "samlConfigured":saml_configured,
            "samlLoginLabel":settings["samlLoginLabel"].as_str().filter(|v| !v.trim().is_empty()).unwrap_or("Sign in with SAML SSO"),
            "hasPassword":settings["password"].as_str().is_some_and(|value| !value.is_empty()),
            "displayName":display_name,
            "loginMethod":login_method,
            "authenticated":session.is_some(),
            "oidcName":non_empty(oidc_name),
            "oidcEmail":non_empty(oidc_email),
            "oidcLogin":is_oidc,
            "samlName":non_empty(saml_name),
            "samlEmail":non_empty(saml_email),
            "samlLogin":is_saml
        }),
    )
}

async fn api_auth_oidc_test(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(input): Json<Value>,
) -> Response {
    let settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => {
            return no_store_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"Unable to read settings"}),
            );
        }
    };
    if settings["requireLogin"] != false && dashboard_session(&state, &headers).is_none() {
        return ApiError::unauthorized("Unauthorized").into_response();
    }

    let issuer_url = input["issuerUrl"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(settings["oidcIssuerUrl"].as_str().unwrap_or_default())
        .trim()
        .trim_end_matches('/');
    let client_id = input["clientId"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(settings["oidcClientId"].as_str().unwrap_or_default())
        .trim();
    let scopes = input["scopes"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(
            settings["oidcScopes"]
                .as_str()
                .unwrap_or("openid profile email"),
        )
        .trim();
    let client_secret = if input
        .as_object()
        .is_some_and(|object| object.contains_key("clientSecret"))
    {
        input["clientSecret"].as_str().unwrap_or_default().trim()
    } else {
        settings["oidcClientSecret"]
            .as_str()
            .unwrap_or_default()
            .trim()
    };
    if issuer_url.is_empty() {
        return ApiError::bad_request("Issuer URL is required").into_response();
    }
    if client_id.is_empty() {
        return ApiError::bad_request("Client ID is required").into_response();
    }
    let Ok(issuer) = reqwest::Url::parse(issuer_url) else {
        return ApiError::bad_request("Issuer URL must be a valid HTTP or HTTPS URL")
            .into_response();
    };
    if !matches!(issuer.scheme(), "http" | "https") {
        return ApiError::bad_request("Issuer URL must be a valid HTTP or HTTPS URL")
            .into_response();
    }
    let discovery_url = format!("{}/.well-known/openid-configuration", issuer_url);
    let discovery = match state
        .http
        .get(&discovery_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => match response.json::<Value>().await {
            Ok(discovery) => discovery,
            Err(_) => {
                return ApiError::upstream("Invalid OIDC discovery response").into_response();
            }
        },
        _ => {
            return ApiError::upstream(format!(
                "Failed to load OIDC discovery document from {discovery_url}"
            ))
            .into_response();
        }
    };
    let origin = public_request_origin(&headers, &uri);
    let redirect_uri = format!("{origin}/api/auth/oidc/callback");
    let (secret_tested, secret_valid, message) = if client_secret.is_empty() {
        (
            false,
            Value::Null,
            "No client secret was provided, so secret validation was skipped.".to_owned(),
        )
    } else {
        let token_endpoint = discovery["token_endpoint"].as_str().unwrap_or_default();
        let probe = state
            .http
            .post(token_endpoint)
            .timeout(Duration::from_secs(10))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("code", "__oidc_test_invalid_code__"),
                ("redirect_uri", redirect_uri.as_str()),
                ("code_verifier", "__oidc_test_invalid_verifier__"),
            ])
            .send()
            .await;
        match probe {
            Ok(response) => {
                let status = response.status();
                let data = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
                let error = data["error"]
                    .as_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let description = data["error_description"]
                    .as_str()
                    .or(data["error"].as_str())
                    .unwrap_or_default();
                if status.is_success() {
                    (
                        true,
                        json!(true),
                        "Client secret was accepted by the token endpoint.".to_owned(),
                    )
                } else if ["invalid_client", "unauthorized_client"].contains(&error.as_str())
                    || (description.to_ascii_lowercase().contains("client")
                        && ["invalid", "failed", "mismatch"]
                            .iter()
                            .any(|term| description.to_ascii_lowercase().contains(term)))
                {
                    (true, json!(false), description.to_owned())
                } else if ["invalid_grant", "invalid_code"].contains(&error.as_str())
                    || description.to_ascii_lowercase().contains("grant")
                    || description.to_ascii_lowercase().contains("code")
                {
                    (
                        true,
                        json!(true),
                        "Client secret was accepted; the token exchange failed only because the test authorization code is invalid.".to_owned(),
                    )
                } else {
                    (
                        true,
                        Value::Null,
                        if description.is_empty() {
                            format!("Token endpoint responded with {status}")
                        } else {
                            description.to_owned()
                        },
                    )
                }
            }
            Err(_) => (
                true,
                Value::Null,
                "Unable to reach the OIDC token endpoint".to_owned(),
            ),
        }
    };
    no_store_json(
        StatusCode::OK,
        json!({
            "ok":secret_valid != json!(false),
            "discoveryOk":true,
            "clientSecretTested":secret_tested,
            "clientSecretValid":secret_valid,
            "issuerUrl":issuer_url,
            "clientId":client_id,
            "scopes":if scopes.is_empty() { "openid profile email" } else { scopes },
            "redirectUri":redirect_uri,
            "authorizationEndpoint":discovery["authorization_endpoint"].as_str().unwrap_or_default(),
            "tokenEndpoint":discovery["token_endpoint"].as_str().unwrap_or_default(),
            "jwksUri":discovery["jwks_uri"].as_str().unwrap_or_default(),
            "message":message,
            "error":if secret_valid == json!(false) {
                format!("Discovery loaded, but the client secret is not valid: {message}")
            } else {
                String::new()
            }
        }),
    )
}

async fn api_auth_oidc_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let origin = public_request_origin(&headers, &uri);
    let settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => return oidc_login_error(&origin, "Unable to read settings", false, &headers),
    };
    let (issuer, client_id, _, scopes) = match oidc_runtime_config(&settings) {
        Ok(config) => config,
        Err(_) => return oidc_login_error(&origin, "oidc_not_configured", false, &headers),
    };
    let discovery = match fetch_oidc_discovery(&state.http, &issuer).await {
        Ok(discovery) => discovery,
        Err(error) => return oidc_login_error(&origin, &error, false, &headers),
    };
    let Some(authorization_endpoint) = discovery["authorization_endpoint"].as_str() else {
        return oidc_login_error(
            &origin,
            "OIDC discovery has no authorization endpoint",
            false,
            &headers,
        );
    };
    let Ok(mut authorization_url) = reqwest::Url::parse(authorization_endpoint) else {
        return oidc_login_error(
            &origin,
            "Invalid OIDC authorization endpoint",
            false,
            &headers,
        );
    };
    if !matches!(authorization_url.scheme(), "http" | "https") {
        return oidc_login_error(
            &origin,
            "Invalid OIDC authorization endpoint",
            false,
            &headers,
        );
    }

    let state_value = random_url_token(16);
    let nonce = random_url_token(16);
    let verifier = random_url_token(32);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let redirect_uri = format!("{origin}/api/auth/oidc/callback");
    authorization_url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("scope", scopes.as_str()),
        ("state", state_value.as_str()),
        ("nonce", nonce.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);

    let mut response = Redirect::to(authorization_url.as_str()).into_response();
    for (name, value) in [
        ("oidc_state", state_value.as_str()),
        ("oidc_nonce", nonce.as_str()),
        ("oidc_code_verifier", verifier.as_str()),
    ] {
        append_auth_cookie(&mut response, name, value, 600, &headers);
    }
    response
}

async fn api_auth_oidc_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let origin = public_request_origin(&headers, &uri);
    let params: HashMap<String, String> = uri
        .query()
        .and_then(|query| serde_urlencoded::from_str(query).ok())
        .unwrap_or_default();
    if let Some(error) = params.get("error") {
        return oidc_login_error(&origin, error, true, &headers);
    }
    let (Some(code), Some(returned_state)) = (params.get("code"), params.get("state")) else {
        return oidc_login_error(&origin, "oidc_missing_code", true, &headers);
    };
    let stored_state = cookie_value(&headers, "oidc_state").unwrap_or_default();
    let stored_nonce = cookie_value(&headers, "oidc_nonce").unwrap_or_default();
    let verifier = cookie_value(&headers, "oidc_code_verifier").unwrap_or_default();
    if stored_state.is_empty()
        || stored_nonce.is_empty()
        || verifier.is_empty()
        || stored_state != *returned_state
    {
        return oidc_login_error(&origin, "oidc_invalid_state", true, &headers);
    }

    let settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => return oidc_login_error(&origin, "Unable to read settings", true, &headers),
    };
    let (issuer, client_id, client_secret, _) = match oidc_runtime_config(&settings) {
        Ok(config) => config,
        Err(_) => return oidc_login_error(&origin, "oidc_not_configured", true, &headers),
    };
    let discovery = match fetch_oidc_discovery(&state.http, &issuer).await {
        Ok(discovery) => discovery,
        Err(error) => return oidc_login_error(&origin, &error, true, &headers),
    };
    let Some(token_endpoint) = discovery["token_endpoint"].as_str() else {
        return oidc_login_error(
            &origin,
            "OIDC discovery has no token endpoint",
            true,
            &headers,
        );
    };
    let Some(jwks_uri) = discovery["jwks_uri"].as_str() else {
        return oidc_login_error(&origin, "OIDC discovery has no JWKS URI", true, &headers);
    };
    let redirect_uri = format!("{origin}/api/auth/oidc/callback");
    let token_response = match state
        .http
        .post(token_endpoint)
        .timeout(Duration::from_secs(15))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return oidc_login_error(&origin, &error.to_string(), true, &headers),
    };
    let token_status = token_response.status();
    let token_data: Value = match token_response.json().await {
        Ok(data) => data,
        Err(error) => return oidc_login_error(&origin, &error.to_string(), true, &headers),
    };
    if !token_status.is_success() {
        let message = token_data["error_description"]
            .as_str()
            .or(token_data["error"].as_str())
            .unwrap_or("OIDC token exchange failed");
        return oidc_login_error(&origin, message, true, &headers);
    }
    let Some(id_token) = token_data["id_token"].as_str() else {
        return oidc_login_error(
            &origin,
            "OIDC provider did not return an id_token",
            true,
            &headers,
        );
    };
    let expected_issuer = discovery["issuer"].as_str().unwrap_or(&issuer);
    let claims = match verify_oidc_id_token(
        &state.http,
        id_token,
        jwks_uri,
        expected_issuer,
        &client_id,
        &stored_nonce,
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) => return oidc_login_error(&origin, &error, true, &headers),
    };
    let display_name = ["preferred_username", "email", "name", "given_name", "sub"]
        .iter()
        .find_map(|key| claims[*key].as_str().filter(|value| !value.is_empty()))
        .unwrap_or("OIDC user");
    let email = claims["email"].as_str().filter(|value| !value.is_empty());
    let session = match auth::create_dashboard_token(
        &state.auth_secret,
        json!({
            "oidc":true,
            "oidcSub":claims["sub"],
            "oidcEmail":email,
            "oidcName":display_name
        }),
    ) {
        Ok(session) => session,
        Err(error) => return oidc_login_error(&origin, &error, true, &headers),
    };
    let mut response = Redirect::to(&format!("{origin}/dashboard")).into_response();
    clear_oidc_cookies(&mut response, &headers);
    append_auth_cookie(
        &mut response,
        "auth_token",
        &session,
        24 * 60 * 60,
        &headers,
    );
    response
}

fn oidc_runtime_config(settings: &Value) -> Result<(String, String, String, String), String> {
    let mode = settings["authMode"].as_str().unwrap_or("password");
    if !["oidc", "both"].contains(&mode) {
        return Err("OIDC login is not enabled".to_owned());
    }
    let issuer = settings["oidcIssuerUrl"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('/');
    let client_id = settings["oidcClientId"].as_str().unwrap_or_default().trim();
    let client_secret = settings["oidcClientSecret"]
        .as_str()
        .unwrap_or_default()
        .trim();
    if issuer.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return Err("OIDC login is not configured".to_owned());
    }
    let issuer_url = reqwest::Url::parse(issuer)
        .map_err(|_| "OIDC issuer URL must be a valid HTTP or HTTPS URL".to_owned())?;
    if !matches!(issuer_url.scheme(), "http" | "https") {
        return Err("OIDC issuer URL must be a valid HTTP or HTTPS URL".to_owned());
    }
    let scopes = settings["oidcScopes"]
        .as_str()
        .filter(|scopes| !scopes.trim().is_empty())
        .unwrap_or("openid profile email")
        .trim();
    Ok((
        issuer.to_owned(),
        client_id.to_owned(),
        client_secret.to_owned(),
        scopes.to_owned(),
    ))
}

async fn fetch_oidc_discovery(client: &reqwest::Client, issuer: &str) -> Result<Value, String> {
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let response = client
        .get(&discovery_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| format!("Failed to load OIDC discovery document from {discovery_url}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Failed to load OIDC discovery document from {discovery_url}"
        ));
    }
    response
        .json()
        .await
        .map_err(|_| "Invalid OIDC discovery response".to_owned())
}

fn random_url_token(byte_count: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = Vec::with_capacity(byte_count);
    while bytes.len() < byte_count {
        bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    URL_SAFE_NO_PAD.encode(&bytes[..byte_count])
}

async fn verify_oidc_id_token(
    client: &reqwest::Client,
    id_token: &str,
    jwks_uri: &str,
    issuer: &str,
    audience: &str,
    nonce: &str,
) -> Result<Value, String> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    let header = decode_header(id_token).map_err(|error| error.to_string())?;
    let response = client
        .get(jwks_uri)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err("Failed to fetch OIDC signing keys".to_owned());
    }
    let jwks: Value = response.json().await.map_err(|error| error.to_string())?;
    let keys = jwks["keys"]
        .as_array()
        .ok_or_else(|| "OIDC JWKS response has no keys".to_owned())?;
    let jwk = if let Some(kid) = header.kid.as_deref() {
        keys.iter().find(|key| key["kid"].as_str() == Some(kid))
    } else if keys.len() == 1 {
        keys.first()
    } else {
        None
    }
    .ok_or_else(|| "No matching OIDC signing key".to_owned())?;
    let algorithm = header.alg;
    if jwk["use"].as_str().is_some_and(|usage| usage != "sig")
        || jwk["alg"]
            .as_str()
            .is_some_and(|key_algorithm| key_algorithm != format!("{algorithm:?}"))
        || jwk["key_ops"].as_array().is_some_and(|operations| {
            !operations
                .iter()
                .any(|operation| operation.as_str() == Some("verify"))
        })
    {
        return Err("OIDC signing key is not valid for this ID token".to_owned());
    }
    let key = match jwk["kty"].as_str() {
        Some("RSA") => DecodingKey::from_rsa_components(
            jwk["n"].as_str().ok_or("Invalid RSA modulus")?,
            jwk["e"].as_str().ok_or("Invalid RSA exponent")?,
        )
        .map_err(|error| error.to_string())?,
        Some("EC") => DecodingKey::from_ec_components(
            jwk["x"].as_str().ok_or("Invalid EC x coordinate")?,
            jwk["y"].as_str().ok_or("Invalid EC y coordinate")?,
        )
        .map_err(|error| error.to_string())?,
        _ => return Err("Unsupported OIDC signing key type".to_owned()),
    };
    if !matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
    ) {
        return Err("Unsupported OIDC ID token signing algorithm".to_owned());
    }
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    let claims = decode::<Value>(id_token, &key, &validation)
        .map_err(|error| format!("Invalid OIDC ID token: {error}"))?
        .claims;
    if claims["nonce"].as_str() != Some(nonce) {
        return Err("OIDC ID token nonce mismatch".to_owned());
    }
    Ok(claims)
}

fn append_auth_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age: u64,
    request_headers: &HeaderMap,
) {
    let secure = std::env::var("AUTH_COOKIE_SECURE").as_deref() == Ok("true")
        || request_headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            == Some("https");
    let cookie = format!(
        "{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn clear_oidc_cookies(response: &mut Response, request_headers: &HeaderMap) {
    for name in ["oidc_state", "oidc_nonce", "oidc_code_verifier"] {
        append_auth_cookie(response, name, "", 0, request_headers);
    }
}

fn oidc_login_error(
    origin: &str,
    error: &str,
    clear_cookies: bool,
    request_headers: &HeaderMap,
) -> Response {
    let mut url = reqwest::Url::parse(&format!("{origin}/login"))
        .unwrap_or_else(|_| reqwest::Url::parse("http://127.0.0.1:20127/login").unwrap());
    url.query_pairs_mut().append_pair("error", error);
    let mut response = Redirect::to(url.as_str()).into_response();
    if clear_cookies {
        clear_oidc_cookies(&mut response, request_headers);
    }
    response
}

async fn api_auth_saml_test(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(input): Json<Value>,
) -> Response {
    let settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => {
            return no_store_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"Unable to read settings"}),
            );
        }
    };
    if settings["requireLogin"] != false && dashboard_session(&state, &headers).is_none() {
        return ApiError::unauthorized("Unauthorized").into_response();
    }
    let entry_point = input["samlEntryPoint"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(settings["samlEntryPoint"].as_str().unwrap_or_default())
        .trim();
    let issuer = input["samlIssuer"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(settings["samlIssuer"].as_str().unwrap_or("urn:9router:sp"))
        .trim();
    let cert = if input
        .as_object()
        .is_some_and(|object| object.contains_key("samlCert"))
    {
        input["samlCert"].as_str().unwrap_or_default()
    } else {
        settings["samlCert"].as_str().unwrap_or_default()
    };
    if entry_point.is_empty() {
        return ApiError::bad_request("Single Sign-On Service URL (samlEntryPoint) is required")
            .into_response();
    }
    if reqwest::Url::parse(entry_point).is_err() {
        return ApiError::bad_request("Single Sign-On Service URL must be a valid URL")
            .into_response();
    }
    if issuer.is_empty() {
        return ApiError::bad_request("SP Entity ID / Issuer (samlIssuer) is required")
            .into_response();
    }
    let cleaned_cert: String = cert
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
        })
        .collect();
    if cleaned_cert.is_empty() {
        return ApiError::bad_request("IdP X.509 Certificate (samlCert) is required")
            .into_response();
    }
    if !cleaned_cert
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return ApiError::bad_request("Invalid IdP X.509 Certificate format").into_response();
    }
    let origin = public_request_origin(&headers, &uri);
    no_store_json(
        StatusCode::OK,
        json!({
            "ok":true,
            "samlEntryPoint":entry_point,
            "samlIssuer":issuer,
            "certValid":true,
            "acsUrl":format!("{origin}/api/auth/saml/acs"),
            "metadataUrl":format!("{origin}/api/auth/saml/metadata"),
            "message":"SAML 2.0 configuration verified successfully."
        }),
    )
}

async fn api_auth_saml_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => {
            return saml_metadata_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "<?xml version=\"1.0\"?><Error>Unable to read settings</Error>",
                false,
            );
        }
    };

    let issuer = settings["samlIssuer"]
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or("urn:9router:sp");
    let origin = public_request_origin(&headers, &uri);
    let entity_id = xml_escape(issuer);
    let acs_url = xml_escape(&format!("{origin}/api/auth/saml/acs"));
    let id = uuid::Uuid::new_v4().simple();
    let metadata = format!(
        "<?xml version=\"1.0\"?>\n<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"{entity_id}\" ID=\"_{id}\">\n  <SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\">\n    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>\n    <AssertionConsumerService index=\"1\" isDefault=\"true\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{acs_url}\"/>\n  </SPSSODescriptor>\n</EntityDescriptor>"
    );
    saml_metadata_response(StatusCode::OK, &metadata, true)
}

fn saml_metadata_response(status: StatusCode, xml: &str, no_cache: bool) -> Response {
    let mut response = (status, xml.to_owned()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    if no_cache {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    response
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn public_request_origin(headers: &HeaderMap, uri: &axum::http::Uri) -> String {
    if let Some(base_url) = std::env::var("BASE_URL")
        .ok()
        .or_else(|| std::env::var("NEXT_PUBLIC_BASE_URL").ok())
        .filter(|value| !value.trim().is_empty())
    {
        return base_url.trim_end_matches('/').to_owned();
    }
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .or_else(|| uri.authority().map(|authority| authority.as_str()))
        .unwrap_or("127.0.0.1:20127");
    let protocol = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or("http");
    format!("{protocol}://{host}")
        .trim_end_matches('/')
        .to_owned()
}

async fn api_cowork_mcp_registry(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let query: HashMap<String, String> = uri
        .query()
        .and_then(|query| serde_urlencoded::from_str(query).ok())
        .unwrap_or_default();
    let force_refresh = query.get("refresh").is_some_and(|value| value == "1");
    let cache = COWORK_MCP_REGISTRY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    if !force_refresh {
        let cached = cache.lock().await;
        if let Some((created_at, data)) = cached.as_ref() {
            if created_at.elapsed() < Duration::from_secs(60 * 60) {
                let mut result = data.clone();
                result["cached"] = json!(true);
                return Json(result).into_response();
            }
        }
    }

    let mut servers = Vec::new();
    let mut cursor = String::new();
    for _ in 0..20 {
        let mut request = state
            .http
            .get("https://api.anthropic.com/mcp-registry/v0/servers")
            .query(&[
                ("limit", "500"),
                ("visibility", "commercial,gsuite,gsuite-google"),
            ]);
        if !cursor.is_empty() {
            request = request.query(&[("cursor", cursor.as_str())]);
        }
        let response = match request
            .header(header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return ApiError::new(StatusCode::BAD_GATEWAY, error.to_string()).into_response();
            }
        };
        if !response.status().is_success() {
            break;
        }
        let payload: Value = match response.json().await {
            Ok(payload) => payload,
            Err(error) => {
                return ApiError::new(StatusCode::BAD_GATEWAY, error.to_string()).into_response();
            }
        };
        for item in payload["servers"].as_array().into_iter().flatten() {
            let server = &item["server"];
            let Some(remote) = server["remotes"]
                .as_array()
                .and_then(|remotes| remotes.first())
            else {
                continue;
            };
            let Some(url) = remote["url"].as_str() else {
                continue;
            };
            if !is_direct_cowork_mcp_url(url) {
                continue;
            }
            let metadata = &item["_meta"]["com.anthropic.api/mcp-registry"];
            if metadata["requiredFields"]
                .as_array()
                .is_some_and(|fields| !fields.is_empty())
            {
                continue;
            }
            let name = server["name"].as_str().unwrap_or_default();
            let tool_names = metadata["toolNames"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let tool_count = tool_names.len();
            servers.push(json!({
                "name":name,
                "slug":metadata["slug"].as_str().unwrap_or(name),
                "title":server["title"].as_str().or(metadata["displayName"].as_str()).unwrap_or(name),
                "description":server["description"].as_str().or(metadata["oneLiner"].as_str()).unwrap_or(""),
                "url":url,
                "transport":if remote["type"] == "sse" {"sse"} else {"http"},
                "oauth":metadata["isAuthless"] != true,
                "toolNames":tool_names,
                "toolCount":tool_count,
                "iconUrl":metadata.get("iconUrl").filter(|value| !value.is_null()).cloned().unwrap_or(Value::Null)
            }));
        }
        cursor = payload["metadata"]["nextCursor"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if cursor.is_empty() {
            break;
        }
    }

    let mut seen = std::collections::HashSet::new();
    servers.retain(|server| {
        server["url"]
            .as_str()
            .is_some_and(|url| seen.insert(url.to_owned()))
    });
    let data = json!({"servers":servers,"total":servers.len()});
    *cache.lock().await = Some((Instant::now(), data.clone()));
    let mut result = data;
    result["cached"] = json!(false);
    Json(result).into_response()
}

async fn api_cowork_mcp_tools(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Response {
    let Some(raw_url) = input["url"].as_str().filter(|url| !url.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"url required"})),
        )
            .into_response();
    };
    let parsed = match reqwest::Url::parse(raw_url) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => url,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"Invalid URL","tools":[]})),
            )
                .into_response();
        }
    };

    let local = is_local_request(&headers, peer);
    let client = if local {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .build()
    } else {
        match cowork_mcp_public_client(&parsed).await {
            Ok(client) => Ok(client),
            Err(()) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"URL not allowed","tools":[]})),
                )
                    .into_response();
            }
        }
    };
    let client = match client {
        Ok(client) => client,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":error.to_string(),"tools":[]})),
            )
                .into_response();
        }
    };

    let endpoint = parsed.as_str();
    let base_headers = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let initialize = json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"9router","version":"1"}}
    });
    let mut init = client.post(endpoint).json(&initialize);
    for (name, value) in base_headers {
        init = init.header(name, value);
    }
    let init = match init.send().await {
        Ok(response) => response,
        Err(error) => {
            return mcp_probe_error(if error.is_timeout() {
                "timeout"
            } else {
                "MCP request failed"
            });
        }
    };
    if matches!(
        init.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Json(json!({"requiresAuth":true,"tools":[]})).into_response();
    }
    if !init.status().is_success() {
        return Json(json!({"error":format!("init {}", init.status().as_u16()),"tools":[]}))
            .into_response();
    }
    let session_id = init
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let _ = init.bytes().await;

    let mut notify = client
        .post(endpoint)
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
    for (name, value) in base_headers {
        notify = notify.header(name, value);
    }
    if !session_id.is_empty() {
        notify = notify.header("mcp-session-id", &session_id);
    }
    let _ = notify.send().await;

    let mut list = client
        .post(endpoint)
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    for (name, value) in base_headers {
        list = list.header(name, value);
    }
    if !session_id.is_empty() {
        list = list.header("mcp-session-id", &session_id);
    }
    let list = match list.send().await {
        Ok(response) => response,
        Err(error) => {
            return mcp_probe_error(if error.is_timeout() {
                "timeout"
            } else {
                "MCP request failed"
            });
        }
    };
    if matches!(
        list.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Json(json!({"requiresAuth":true,"tools":[]})).into_response();
    }
    if !list.status().is_success() {
        return Json(json!({"error":format!("tools/list {}", list.status().as_u16()),"tools":[]}))
            .into_response();
    }
    let is_sse = list
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"));
    let parsed = if is_sse {
        let body = match list.text().await {
            Ok(body) => body,
            Err(_) => return mcp_probe_error("Unable to read MCP response"),
        };
        body.lines()
            .filter_map(|line| line.strip_prefix("data:").map(str::trim))
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|message| message["id"] == 2 && message["result"].is_object())
    } else {
        list.json::<Value>().await.ok()
    };
    let tools = parsed
        .as_ref()
        .and_then(|message| message["result"]["tools"].as_array())
        .map(|tools| {
            tools
                .iter()
                .map(|tool| {
                    json!({
                        "name":tool["name"],
                        "description":tool["description"].as_str().unwrap_or_default()
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Json(json!({"tools":tools})).into_response()
}

fn mcp_probe_error(message: &str) -> Response {
    Json(json!({"error":message,"tools":[]})).into_response()
}

async fn cowork_mcp_public_client(url: &reqwest::Url) -> Result<reqwest::Client, ()> {
    let host = url.host_str().ok_or(())?;
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized == "localhost"
        || normalized == "ip6-localhost"
        || normalized == "ip6-loopback"
        || [".localhost", ".local", ".internal"]
            .iter()
            .any(|suffix| normalized.ends_with(suffix))
    {
        return Err(());
    }
    let port = url.port_or_known_default().ok_or(())?;
    let addrs = if let Ok(ip) = normalized.parse::<std::net::IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((normalized.as_str(), port))
            .await
            .map_err(|_| ())?
            .collect::<Vec<_>>()
    };
    if addrs.is_empty() || addrs.iter().any(|addr| !is_public_ip(addr.ip())) {
        return Err(());
    }
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&normalized, &addrs)
        .build()
        .map_err(|_| ())
}

fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            let cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !cgnat
                && octets[0] != 0
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(std::net::IpAddr::V4(mapped));
            }
            let segments = ip.segments();
            // Global unicast is 2000::/3. Deny all other special-use IPv6 ranges.
            (segments[0] & 0xe000) == 0x2000
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
    }
}

fn is_direct_cowork_mcp_url(value: &str) -> bool {
    if value.contains('<') || value.contains('{') {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    let host = url.host_str().unwrap_or_default();
    !host.eq_ignore_ascii_case("mcp.claude.com")
        && !host.to_ascii_lowercase().ends_with(".mcp.claude.com")
        && !(host.eq_ignore_ascii_case("api.anthropic.com") && url.path().starts_with("/mcp"))
}

async fn api_count_anthropic_tokens(Json(body): Json<Value>) -> Response {
    let input_tokens = estimate_anthropic_input_tokens(&body);
    let mut response = Json(json!({"input_tokens":input_tokens})).into_response();
    add_count_tokens_cors_headers(response.headers_mut(), "POST, OPTIONS");
    response
}

async fn api_count_anthropic_tokens_options() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_count_tokens_cors_headers(response.headers_mut(), "POST, OPTIONS");
    response
}

fn add_count_tokens_cors_headers(headers: &mut HeaderMap, methods: &'static str) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(methods),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
}

fn estimate_anthropic_input_tokens(body: &Value) -> u64 {
    let mut total =
        count_json_value_chars(body.get("system")) + count_json_value_chars(body.get("tools"));

    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            let Some(content) = message.get("content") else {
                continue;
            };
            total += match content {
                Value::String(value) => javascript_string_length(value),
                Value::Array(blocks) => blocks.iter().map(count_anthropic_block_chars).sum(),
                value => count_json_value_chars(Some(value)),
            };
        }
    }

    total.div_ceil(4)
}

fn count_anthropic_block_chars(block: &Value) -> u64 {
    match block.get("type").and_then(Value::as_str) {
        Some("text") => count_json_value_chars(block.get("text")),
        Some("tool_use") => {
            count_json_value_chars(block.get("name")) + count_json_value_chars(block.get("input"))
        }
        Some("tool_result") => count_json_value_chars(block.get("content")),
        Some("thinking") => count_json_value_chars(block.get("thinking")),
        _ => count_json_value_chars(Some(block)),
    }
}

fn count_json_value_chars(value: Option<&Value>) -> u64 {
    match value {
        None | Some(Value::Null) => 0,
        Some(Value::String(value)) => javascript_string_length(value),
        Some(Value::Number(value)) => javascript_string_length(&value.to_string()),
        Some(Value::Bool(value)) => javascript_string_length(if *value { "true" } else { "false" }),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| count_json_value_chars(Some(value)))
            .sum(),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| javascript_string_length(key) + count_json_value_chars(Some(value)))
            .sum(),
    }
}

fn javascript_string_length(value: &str) -> u64 {
    value.encode_utf16().count() as u64
}

async fn api_version(State(state): State<AppState>) -> Json<Value> {
    let package: Value =
        serde_json::from_str(include_str!("../../package.json")).unwrap_or_else(|_| json!({}));
    let current_version = package["version"].as_str().unwrap_or("0.0.0");
    let cache = VERSION_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    let cached = {
        let cache = cache.lock().await;
        cache
            .as_ref()
            .filter(|(fetched_at, _)| fetched_at.elapsed() < Duration::from_secs(3600))
            .map(|(_, version)| version.clone())
    };
    let latest_version = match cached {
        Some(version) => version,
        None => {
            let latest = match state
                .http
                .get("https://registry.npmjs.org/9router/latest")
                .timeout(Duration::from_secs(4))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => response
                    .json::<Value>()
                    .await
                    .ok()
                    .and_then(|package| package["version"].as_str().map(str::to_owned)),
                _ => None,
            };
            if let Some(version) = &latest {
                *cache.lock().await = Some((Instant::now(), Some(version.clone())));
            }
            latest
        }
    };
    let has_update = latest_version.as_deref().is_some_and(|latest| {
        compare_versions(latest, current_version) == std::cmp::Ordering::Greater
    });
    Json(json!({
        "currentVersion":current_version,
        "latestVersion":latest_version,
        "hasUpdate":has_update
    }))
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let parse = |version: &str| {
        let version = version.split(['-', '+']).next().unwrap_or(version);
        let mut parts = version
            .split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0));
        [
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        ]
    };
    parse(left).cmp(&parse(right))
}

async fn api_require_login_status(State(state): State<AppState>) -> Json<Value> {
    let settings = read_settings(&state.db).await.unwrap_or_else(|_| json!({}));
    Json(json!({
        "requireLogin":settings["requireLogin"] != false,
        "tunnelDashboardAccess":settings["tunnelDashboardAccess"] != false,
        "tunnelUrl":settings["tunnelUrl"].as_str().unwrap_or_default(),
        "tailscaleUrl":settings["tailscaleUrl"].as_str().unwrap_or_default(),
    }))
}

async fn api_proxy_test(Json(input): Json<Value>) -> Response {
    let proxy_url = input["proxyUrl"].as_str().unwrap_or_default().trim();
    if proxy_url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"status":400,"error":"proxyUrl is required"})),
        )
            .into_response();
    }
    let test_url = input["testUrl"]
        .as_str()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or("https://google.com/")
        .trim();
    let timeout_ms = input["timeoutMs"]
        .as_u64()
        .filter(|timeout| *timeout > 0)
        .unwrap_or(8_000)
        .min(30_000);
    let proxy = match reqwest::Proxy::all(proxy_url) {
        Ok(proxy) => proxy,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"ok":false,"status":400,"error":format!("Invalid proxy URL: {error}")}),
                ),
            )
                .into_response();
        }
    };
    let client =
        match reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_millis(timeout_ms))
            .build()
        {
            Ok(client) => client,
            Err(error) => return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"ok":false,"status":400,"error":format!("Invalid proxy URL: {error}")}),
                ),
            )
                .into_response(),
        };
    let started = Instant::now();
    match client
        .head(test_url)
        .header(header::USER_AGENT, "9Router")
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            Json(json!({
                "ok":status.is_success(),
                "status":status.as_u16(),
                "statusText":status.canonical_reason().unwrap_or_default(),
                "url":test_url,
                "elapsedMs":started.elapsed().as_millis(),
            }))
            .into_response()
        }
        Err(error) => {
            let message = if error.is_timeout() {
                "Proxy test timed out".to_string()
            } else {
                error.to_string()
            };
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok":false,"status":500,"error":message})),
            )
                .into_response()
        }
    }
}

async fn api_set_locale(Json(input): Json<Value>) -> Response {
    const LOCALES: &[&str] = &[
        "en", "vi", "zh-CN", "zh-TW", "ja", "pt-BR", "pt-PT", "ko", "es", "de", "fr", "he", "ar",
        "ru", "pl", "cs", "nl", "tr", "uk", "tl", "id", "km", "th", "hi", "bn", "ur", "ro", "sv",
        "it", "el", "hu", "fi", "da", "no", "fa",
    ];
    let Some(locale) = input["locale"].as_str() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid locale"})),
        )
            .into_response();
    };
    let locale = if locale == "zh" { "zh-CN" } else { locale };
    if !LOCALES.contains(&locale) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid locale"})),
        )
            .into_response();
    }
    let mut response = Json(json!({"success":true,"locale":locale})).into_response();
    if let Ok(cookie) = HeaderValue::from_str(&format!(
        "locale={locale}; Path=/; Max-Age=31536000; SameSite=Lax"
    )) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

async fn api_tags() -> Response {
    let mut response = Response::new(Body::from(include_str!("ollama_models.json")));
    for (name, value) in [
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ),
        (
            axum::http::HeaderName::from_static("access-control-allow-origin"),
            HeaderValue::from_static("*"),
        ),
        (
            axum::http::HeaderName::from_static("access-control-allow-methods"),
            HeaderValue::from_static("GET, OPTIONS"),
        ),
        (
            axum::http::HeaderName::from_static("access-control-allow-headers"),
            HeaderValue::from_static("*"),
        ),
    ] {
        response.headers_mut().insert(name, value);
    }
    response
}

async fn api_tags_options() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    for (name, value) in [
        ("access-control-allow-origin", "*"),
        ("access-control-allow-methods", "GET, OPTIONS"),
        ("access-control-allow-headers", "*"),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    response
}

async fn api_auth_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Response {
    const MAX_FAILURES: u32 = 5;
    const LOCK_STEPS: [u64; 4] = [30, 120, 600, 1800];
    const RESET_WINDOW: Duration = Duration::from_secs(60 * 60);
    const RESET_HINT: &str =
        "Forgot password? Reset to default via 9Router CLI → Settings → Reset Password to Default.";
    let ip = login_client_ip(&headers, peer);
    let now = Instant::now();
    {
        let mut attempts = state.login_attempts.lock().await;
        if attempts.get(&ip).is_some_and(|entry| {
            now.duration_since(entry.last_failure) > RESET_WINDOW
                && entry.locked_until.is_none_or(|until| now >= until)
        }) {
            attempts.remove(&ip);
        }
        if let Some(entry) = attempts.get(&ip) {
            if let Some(until) = entry.locked_until.filter(|until| now < *until) {
                let retry_after = until.duration_since(now).as_secs().max(1);
                let mut response = no_store_json(
                    StatusCode::TOO_MANY_REQUESTS,
                    json!({"error":format!("Too many failed attempts. Try again in {retry_after}s. {RESET_HINT}"),"retryAfter":retry_after,"resetHint":RESET_HINT}),
                );
                if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                return response;
            }
        }
    }

    let password = input["password"].as_str().unwrap_or_default();
    let settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => {
            return no_store_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"Unable to read settings"}),
            );
        }
    };
    if !settings["tunnelDashboardAccess"].as_bool().unwrap_or(true)
        && is_tunnel_request(&headers, &settings)
    {
        return no_store_json(
            StatusCode::FORBIDDEN,
            json!({"error":"Dashboard access via tunnel is disabled"}),
        );
    }
    let auth_mode = settings["authMode"].as_str().unwrap_or("password");
    let sso_type = settings["ssoType"]
        .as_str()
        .unwrap_or(if auth_mode == "saml" { "saml" } else { "oidc" });
    let oidc_configured = ["oidcIssuerUrl", "oidcClientId", "oidcClientSecret"]
        .iter()
        .all(|key| {
            settings[*key]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        });
    let saml_configured = ["samlEntryPoint", "samlIssuer", "samlCert"]
        .iter()
        .all(|key| {
            settings[*key]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        });
    if matches!(auth_mode, "sso" | "saml" | "oidc")
        && ((sso_type == "saml" && saml_configured) || (sso_type == "oidc" && oidc_configured))
    {
        let login_type = if sso_type == "saml" { "SAML" } else { "OIDC" };
        return no_store_json(
            StatusCode::FORBIDDEN,
            json!({"error":format!("Password login is disabled. Use {login_type} SSO sign in.")}),
        );
    }

    let stored_hash = settings["password"]
        .as_str()
        .filter(|value| !value.is_empty());
    let is_valid = if let Some(hash) = stored_hash {
        bcrypt::verify(password, hash).unwrap_or(false)
    } else {
        password == std::env::var("INITIAL_PASSWORD").unwrap_or_else(|_| "123456".into())
    };
    if !is_valid {
        let (remaining_before_lock, retry_after) = {
            let mut attempts = state.login_attempts.lock().await;
            let entry = attempts.entry(ip.clone()).or_insert(LoginAttempt {
                failures: 0,
                lock_level: 0,
                last_failure: now,
                locked_until: None,
            });
            entry.failures += 1;
            entry.last_failure = now;
            if entry.failures >= MAX_FAILURES {
                let lock_seconds = LOCK_STEPS[entry.lock_level.min(LOCK_STEPS.len() - 1)];
                entry.lock_level += 1;
                entry.failures = 0;
                entry.locked_until = Some(now + Duration::from_secs(lock_seconds));
                (0, Some(lock_seconds))
            } else {
                (MAX_FAILURES - entry.failures, None)
            }
        };
        if let Some(retry_after) = retry_after {
            let mut response = no_store_json(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"error":format!("Too many failed attempts. Try again in {retry_after}s. {RESET_HINT}"),"retryAfter":retry_after,"resetHint":RESET_HINT}),
            );
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
        return no_store_json(
            StatusCode::UNAUTHORIZED,
            json!({"error":format!("Invalid password. {remaining_before_lock} attempt(s) left before lockout."),"remainingBeforeLock":remaining_before_lock}),
        );
    }

    state.login_attempts.lock().await.remove(&ip);
    let must_change_password = stored_hash.is_none()
        && std::env::var("INITIAL_PASSWORD").is_err()
        && !is_local_request(&headers, peer);
    if must_change_password {
        return no_store_json(
            StatusCode::FORBIDDEN,
            json!({"success":false,"error":"Default password must be changed before remote access. Change it from the local machine (or set INITIAL_PASSWORD).","mustChangePassword":true}),
        );
    }
    let token = match auth::create_dashboard_token(&state.auth_secret, json!({})) {
        Ok(token) => token,
        Err(_) => {
            return no_store_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"Unable to create session"}),
            );
        }
    };
    let secure = std::env::var("AUTH_COOKIE_SECURE").as_deref() == Ok("true")
        || headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            == Some("https");
    let secure_attribute = if secure { "; Secure" } else { "" };
    let mut response = no_store_json(
        StatusCode::OK,
        json!({"success":true,"mustChangePassword":false}),
    );
    if let Ok(cookie) = HeaderValue::from_str(&format!(
        "auth_token={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400{secure_attribute}"
    )) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

async fn api_auth_logout(headers: HeaderMap) -> Response {
    let secure = std::env::var("AUTH_COOKIE_SECURE").as_deref() == Ok("true")
        || headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            == Some("https");
    let secure_attribute = if secure { "; Secure" } else { "" };
    let mut response = no_store_json(StatusCode::OK, json!({"success":true}));
    for cookie in [
        "auth_token",
        "oidc_state",
        "oidc_nonce",
        "oidc_code_verifier",
    ] {
        if let Ok(value) = HeaderValue::from_str(&format!(
            "{cookie}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure_attribute}"
        )) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

async fn api_auth_reset_password(State(state): State<AppState>) -> Response {
    let mut settings = match read_settings(&state.db).await {
        Ok(settings) => settings,
        Err(_) => {
            return no_store_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"Unable to read settings"}),
            );
        }
    };
    settings["password"] = Value::Null;
    match sqlx::query(
        "INSERT INTO settings(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
    )
    .bind(settings.to_string())
    .execute(&state.db)
    .await
    {
        Ok(_) => no_store_json(StatusCode::OK, json!({"success":true})),
        Err(_) => no_store_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"Unable to reset password"}),
        ),
    }
}

async fn api_import_codex_token(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    let Some(token) = input
        .get("accessToken")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Access token is required"})),
        )
            .into_response();
    };
    let mut email: Option<String> = None;
    let mut specific = json!({"authMethod":"access_token"});
    let payload = token.split('.').nth(1).and_then(decode_jwt_payload);
    if let Some(payload) = payload {
        let auth = &payload["https://api.openai.com/auth"];
        let profile = &payload["https://api.openai.com/profile"];
        email = profile["email"]
            .as_str()
            .or(payload["email"].as_str())
            .or(payload["preferred_username"].as_str())
            .map(str::to_owned);
        if let Some(value) = auth["chatgpt_account_id"].as_str() {
            specific["chatgptAccountId"] = json!(value);
        }
        if let Some(value) = auth["chatgpt_plan_type"].as_str() {
            specific["chatgptPlanType"] = json!(value);
        }
        if !payload["exp"].is_null() {
            specific["jwtExp"] = payload["exp"].clone();
        }
    }
    let name = input
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .or_else(|| email.clone())
        .unwrap_or_else(|| "ChatGPT Access Token".into());
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    let data = json!({"apiKey":"","accessToken":token,"refreshToken":null,"expiresAt":null,"providerSpecificData":specific,"testStatus":"active"});
    if let Err(error)=sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?, ?,?,1,1,?,?,?)")
        .bind(&id).bind("codex").bind("access_token").bind(&name).bind(email.as_deref()).bind(data.to_string()).bind(&now).bind(&now).execute(&state.db).await {
        return (StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"error":error.to_string()}))).into_response();
    }
    Json(json!({"success":true,"connection":{"id":id,"provider":"codex","email":email,"name":name,"workspace":specific["chatgptAccountId"],"plan":specific["chatgptPlanType"]}})).into_response()
}

fn decode_jwt_payload(segment: &str) -> Option<Value> {
    use base64::Engine;
    let normalized = segment.replace('-', "+").replace('_', "/");
    let padded = format!(
        "{}{}",
        normalized,
        "=".repeat((4 - normalized.len() % 4) % 4)
    );
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(padded)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn api_import_gitlab_pat(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    let token = input
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Personal Access Token is required"})),
        )
            .into_response();
    }
    let base = input
        .get("baseUrl")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("https://gitlab.com")
        .trim()
        .trim_end_matches('/');
    let url = format!("{base}/api/v4/user");
    let mut headers = HeaderMap::new();
    if let Err((status, message)) = insert_header(&mut headers, "Private-Token", token) {
        return (status, Json(json!({"error":message}))).into_response();
    }
    if let Err((status, message)) = insert_header(&mut headers, "Accept", "application/json") {
        return (status, Json(json!({"error":message}))).into_response();
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    let response = match provider_request_headers(&client, "GET", &url, headers, None).await {
        Ok(response) => response,
        Err((status, message)) => return (status, Json(json!({"error":message}))).into_response(),
    };
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return (StatusCode::UNAUTHORIZED,Json(json!({"error":format!("GitLab token verification failed: {}",text.chars().take(500).collect::<String>()),"upstreamStatus":status.as_u16()}))).into_response();
    }
    let user: Value = match response.json().await {
        Ok(user) => user,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":format!("Invalid GitLab user response: {error}")})),
            )
                .into_response();
        }
    };
    let email = user["email"]
        .as_str()
        .or(user["public_email"].as_str())
        .unwrap_or_default();
    let username = user["username"].as_str().unwrap_or_default();
    let display =
        user["name"]
            .as_str()
            .filter(|v| !v.is_empty())
            .unwrap_or(if !username.is_empty() {
                username
            } else {
                email
            });
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    let data = json!({"apiKey":"","accessToken":token,"refreshToken":null,"expiresAt":null,"displayName":display,"testStatus":"active","providerSpecificData":{"username":username,"email":email,"name":user["name"].as_str().unwrap_or_default(),"baseUrl":base,"authKind":"personal_access_token"}});
    if let Err(error)=sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?, ?,?,1,1,?,?,?)")
        .bind(&id).bind("gitlab").bind("oauth").bind(display).bind(if email.is_empty(){None}else{Some(email)}).bind(data.to_string()).bind(&now).bind(&now).execute(&state.db).await{
        return (StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"error":error.to_string()}))).into_response();
    }
    Json(json!({"success":true})).into_response()
}

async fn api_import_iflow_cookie(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    let cookie = input
        .get("cookie")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if cookie.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Cookie is required"})),
        )
            .into_response();
    }
    if !cookie.contains("BXAuth=") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Cookie must contain BXAuth field"})),
        )
            .into_response();
    }
    let normalized = if cookie.ends_with(';') {
        cookie.to_string()
    } else {
        format!("{cookie};")
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
    let mut get_headers = HeaderMap::new();
    for (name, value) in [
        ("Cookie", normalized.as_str()),
        ("Accept", "application/json, text/plain, */*"),
        ("User-Agent", user_agent),
        ("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"),
    ] {
        if let Err((status, message)) = insert_header(&mut get_headers, name, value) {
            return (status, Json(json!({"error":message}))).into_response();
        }
    }
    let get_response = match provider_request_headers(
        &client,
        "GET",
        "https://platform.iflow.cn/api/openapi/apikey",
        get_headers,
        None,
    )
    .await
    {
        Ok(response) => response,
        Err((status, message)) => return (status, Json(json!({"error":message}))).into_response(),
    };
    if !get_response.status().is_success() {
        let status = get_response.status();
        let body = get_response.text().await.unwrap_or_default();
        return (
            status,
            Json(json!({"error":format!("Failed to fetch API key info: {body}")})),
        )
            .into_response();
    }
    let get_result: Value = match get_response.json().await {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    if get_result["success"] != true {
        return (StatusCode::BAD_REQUEST,Json(json!({"error":format!("API key fetch failed: {}",get_result["message"].as_str().unwrap_or_default())}))).into_response();
    }
    let key_name = get_result["data"]["name"].as_str().unwrap_or_default();
    if key_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Missing name in API key info"})),
        )
            .into_response();
    }
    let mut post_headers = HeaderMap::new();
    for (name, value) in [
        ("Cookie", normalized.as_str()),
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/plain, */*"),
        ("User-Agent", user_agent),
        ("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"),
        ("Origin", "https://platform.iflow.cn"),
        ("Referer", "https://platform.iflow.cn/"),
    ] {
        if let Err((status, message)) = insert_header(&mut post_headers, name, value) {
            return (status, Json(json!({"error":message}))).into_response();
        }
    }
    let post_response = match provider_request_headers(
        &client,
        "POST",
        "https://platform.iflow.cn/api/openapi/apikey",
        post_headers,
        Some(json!({"name":key_name})),
    )
    .await
    {
        Ok(response) => response,
        Err((status, message)) => return (status, Json(json!({"error":message}))).into_response(),
    };
    if !post_response.status().is_success() {
        let status = post_response.status();
        let body = post_response.text().await.unwrap_or_default();
        return (
            status,
            Json(json!({"error":format!("Failed to refresh API key: {body}")})),
        )
            .into_response();
    }
    let post_result: Value = match post_response.json().await {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    if post_result["success"] != true {
        return (StatusCode::BAD_REQUEST,Json(json!({"error":format!("API key refresh failed: {}",post_result["message"].as_str().unwrap_or_default())}))).into_response();
    }
    let refreshed = &post_result["data"];
    let api_key = refreshed["apiKey"].as_str().unwrap_or_default();
    if api_key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Missing API key in response"})),
        )
            .into_response();
    }
    let bxauth = normalized
        .split(';')
        .find_map(|part| part.trim().strip_prefix("BXAuth="))
        .unwrap_or_default();
    let saved_cookie = if bxauth.is_empty() {
        String::new()
    } else {
        format!("BXAuth={bxauth};")
    };
    let name = refreshed["name"]
        .as_str()
        .filter(|v| !v.is_empty())
        .unwrap_or(key_name);
    let expires = refreshed["expireTime"].clone();
    let now = timestamp();
    let id = uuid::Uuid::new_v4().to_string();
    let data = json!({"apiKey":api_key,"providerSpecificData":{"cookie":saved_cookie,"expireTime":expires},"testStatus":"active"});
    if let Err(error)=sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?, ?,?,1,1,?,?,?)")
        .bind(&id).bind("iflow").bind("cookie").bind(name).bind(name).bind(data.to_string()).bind(&now).bind(&now).execute(&state.db).await{
        return (StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"error":error.to_string()}))).into_response();
    }
    Json(json!({"success":true,"connection":{"id":id,"provider":"iflow","email":name,"apiKey":format!("{}...",api_key.chars().take(10).collect::<String>()),"expireTime":expires}})).into_response()
}

async fn api_import_xiaomi_mimo_key(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    use sqlx::Row;
    let api_key = input["apiKey"].as_str().unwrap_or_default().trim();
    let uid = input["uid"].as_str().filter(|v| !v.is_empty());
    let pass_token = input["mimoPassToken"].as_str().unwrap_or_default().trim();
    let session_only = api_key.is_empty() && !pass_token.is_empty();
    if api_key.is_empty() && pass_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"API key is required"})),
        )
            .into_response();
    }
    if !api_key.is_empty() && !api_key.starts_with("sk-") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid key format — expected sk- prefix"})),
        )
            .into_response();
    }
    let base = input["baseUrl"]
        .as_str()
        .filter(|v| !v.is_empty())
        .unwrap_or("https://api.xiaomimimo.com/v1")
        .trim_end_matches('/');
    let region_input = input["region"].as_str().filter(|v| !v.is_empty());
    let region = region_input.unwrap_or("cn");
    let mut validated = false;
    let mut model_count = 0usize;
    if !api_key.is_empty() {
        let mut headers = HeaderMap::new();
        if let Err((status, message)) =
            insert_header(&mut headers, "Authorization", &format!("Bearer {api_key}"))
        {
            return (status, Json(json!({"error":message}))).into_response();
        }
        if let Err((status, message)) = insert_header(&mut headers, "X-Mimo-Source", "mimocode-cli")
        {
            return (status, Json(json!({"error":message}))).into_response();
        }
        if let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            if let Ok(response) =
                provider_request_headers(&client, "GET", &format!("{base}/models"), headers, None)
                    .await
            {
                if response.status().is_success() {
                    let payload = response.json::<Value>().await.unwrap_or_default();
                    model_count = payload["data"].as_array().map(Vec::len).unwrap_or(0);
                    validated = true;
                }
            }
        }
    }
    let target_email = uid.map(|value| format!("{value}@xiaomi"));
    let mimo_user_id = input["mimoUserId"].as_str();
    let rows=match sqlx::query("SELECT id,email,name,data FROM providerConnections WHERE provider='xiaomi-mimo' ORDER BY createdAt").fetch_all(&state.db).await{Ok(rows)=>rows,Err(error)=>return ApiError::upstream(error.to_string()).into_response()};
    let mut existing: Option<(String, Option<String>, Option<String>, Value)> = None;
    for row in rows {
        let data: Value = serde_json::from_str(&row.get::<String, _>("data")).unwrap_or_default();
        let row_email: Option<String> = row.get("email");
        let same_uid = target_email
            .as_ref()
            .is_some_and(|email| row_email.as_ref() == Some(email));
        let same_key = !api_key.is_empty() && data["accessToken"].as_str() == Some(api_key);
        let same_session = session_only
            && mimo_user_id
                .is_some_and(|id| data["providerSpecificData"]["mimoUserId"].as_str() == Some(id))
            && region_input.is_none_or(|region| {
                data["providerSpecificData"]["region"]
                    .as_str()
                    .unwrap_or("cn")
                    == region
            });
        if same_uid || same_key || same_session {
            existing = Some((row.get("id"), row_email, row.get("name"), data));
            break;
        }
    }
    let mut fields = vec![("modelCount", json!(model_count))];
    if let Some((id, email, name, mut data)) = existing {
        if !api_key.is_empty() {
            data["accessToken"] = json!(api_key);
        }
        if !data["providerSpecificData"].is_object() {
            data["providerSpecificData"] = json!({});
        }
        let old_specific = data["providerSpecificData"].clone();
        fields.push((
            "baseUrl",
            json!(if !api_key.is_empty() {
                base
            } else {
                old_specific["baseUrl"].as_str().unwrap_or(base)
            }),
        ));
        fields.push((
            "region",
            json!(region_input.unwrap_or(old_specific["region"].as_str().unwrap_or("cn"))),
        ));
        fields.push((
            "authMethod",
            json!(if session_only {
                "session"
            } else {
                old_specific["authMethod"].as_str().unwrap_or("api_key")
            }),
        ));
        fields.push((
            "provider",
            json!(if session_only {
                "Session Login"
            } else {
                old_specific["provider"].as_str().unwrap_or("API Key")
            }),
        ));
        for key in ["uid", "mimoPassToken", "mimoUserId", "mimoCUserId"] {
            if !input[key].is_null() && !input[key].as_str().is_some_and(str::is_empty) {
                fields.push((key, input[key].clone()));
            }
        }
        for (key, value) in fields {
            data["providerSpecificData"][key] = value;
        }
        if validated {
            data["testStatus"] = json!("active");
        }
        let now = timestamp();
        if let Err(error) =
            sqlx::query("UPDATE providerConnections SET data=?,updatedAt=? WHERE id=?")
                .bind(data.to_string())
                .bind(&now)
                .bind(&id)
                .execute(&state.db)
                .await
        {
            return ApiError::upstream(error.to_string()).into_response();
        }
        let display = data["displayName"].as_str().map(str::to_owned).or(name);
        return Json(json!({"success":true,"validated":validated,"modelCount":model_count,"updated":true,"connection":{"id":id,"provider":"xiaomi-mimo","email":email,"displayName":display}})).into_response();
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    let expires = (chrono::Utc::now() + chrono::Duration::days(365))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let display = uid
        .map(|uid| {
            format!(
                "Xiaomi {uid}{}",
                if session_only { " (Session)" } else { "" }
            )
        })
        .unwrap_or_else(|| "Xiaomi MiMo".into());
    fields.push(("uid", json!(uid)));
    fields.push(("baseUrl", json!(base)));
    fields.push(("region", json!(region)));
    fields.push((
        "authMethod",
        json!(if session_only { "session" } else { "api_key" }),
    ));
    fields.push((
        "provider",
        json!(if session_only {
            "Session Login"
        } else {
            "API Key"
        }),
    ));
    fields.push(("mimoPassToken", input["mimoPassToken"].clone()));
    fields.push(("mimoUserId", input["mimoUserId"].clone()));
    fields.push(("mimoCUserId", input["mimoCUserId"].clone()));
    let mut specific = json!({});
    for (key, value) in fields {
        specific[key] = value;
    }
    let data = json!({"apiKey":"","accessToken":if api_key.is_empty(){Value::Null}else{json!(api_key)},"refreshToken":null,"expiresAt":expires,"displayName":display,"providerSpecificData":specific,"testStatus":if validated||session_only{"active"}else{"untested"}});
    let auth = if session_only { "oauth" } else { "api_key" };
    if let Err(error)=sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?, ?,?,1,1,?,?,?)").bind(&id).bind("xiaomi-mimo").bind(auth).bind(&display).bind(target_email.as_deref()).bind(data.to_string()).bind(&now).bind(&now).execute(&state.db).await{return ApiError::upstream(error.to_string()).into_response();}
    Json(json!({"success":true,"validated":validated,"modelCount":model_count,"connection":{"id":id,"provider":"xiaomi-mimo","email":target_email,"displayName":display}})).into_response()
}

async fn api_import_zed_token(State(state): State<AppState>, Json(input): Json<Value>) -> Response {
    let token = input["accessToken"].as_str().unwrap_or_default().trim();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Access token is required"})),
        )
            .into_response();
    }
    let user_id = input
        .get("userId")
        .map(|v| {
            if let Some(s) = v.as_str() {
                s.to_string()
            } else if v.is_number() {
                v.to_string()
            } else {
                String::new()
            }
        })
        .unwrap_or_default();
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"User id is required"})),
        )
            .into_response();
    }
    let system_id = input["systemId"]
        .as_str()
        .filter(|v| !v.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut headers = HeaderMap::new();
    if let Err((status, message)) = insert_header(&mut headers, "Accept", "application/json") {
        return (status, Json(json!({"error":message}))).into_response();
    }
    if let Err((status, message)) =
        insert_header(&mut headers, "Authorization", &format!("{user_id} {token}"))
    {
        return (status, Json(json!({"error":message}))).into_response();
    }
    if let Err((status, message)) = insert_header(&mut headers, "x-zed-system-id", &system_id) {
        return (status, Json(json!({"error":message}))).into_response();
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    let response = match provider_request_headers(
        &client,
        "GET",
        "https://cloud.zed.dev/client/users/me",
        headers,
        None,
    )
    .await
    {
        Ok(response) => response,
        Err((_, message)) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error":message}))).into_response();
        }
    };
    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        let parsed = serde_json::from_str::<Value>(&body).unwrap_or_default();
        let message = parsed["message"]
            .as_str()
            .or(parsed["error"]["message"].as_str())
            .or(parsed["error"].as_str())
            .unwrap_or(&body);
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":message}))).into_response();
    }
    let user: Value = match response.json().await {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    let organization_id = zed_org_id(&user);
    let email = user["email"].as_str();
    let display_name = user["name"]
        .as_str()
        .or(user["display_name"].as_str())
        .or(user["username"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Zed {user_id}"));
    let specific = json!({"authMethod":"imported","userId":user_id,"systemId":system_id,"organizationId":organization_id});
    let data = json!({"apiKey":"","accessToken":token,"refreshToken":null,"expiresAt":null,"displayName":display_name,"providerSpecificData":specific,"testStatus":"active"});
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    if let Err(error)=sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?, ?,?,1,1,?,?,?)").bind(&id).bind("zed").bind("oauth").bind(&display_name).bind(email).bind(data.to_string()).bind(&now).bind(&now).execute(&state.db).await{return ApiError::upstream(error.to_string()).into_response();}
    Json(json!({"success":true,"connection":{"id":id,"provider":"zed","email":email,"displayName":display_name}})).into_response()
}

async fn api_cursor_import_instructions() -> Response {
    let linux = "~/.config/Cursor/User/globalStorage/state.vscdb";
    let macos = "/Users/<user>/Library/Application Support/Cursor/User/globalStorage/state.vscdb";
    let windows = r"%APPDATA%\Cursor\User\globalStorage\state.vscdb";
    Json(json!({
        "provider":"cursor","method":"import_token",
        "instructions":{
            "title":"How to get your Cursor token",
            "steps":["1. Open Cursor IDE and make sure you're logged in","2. Find the state.vscdb file:",format!("   - Linux: {linux}"),format!("   - macOS: {macos}"),format!("   - Windows: {windows}"),"3. Open the database with SQLite browser or CLI:","   sqlite3 state.vscdb \"SELECT value FROM itemTable WHERE key='cursorAuth/accessToken'\"","4. Also get the machine ID:","   sqlite3 state.vscdb \"SELECT value FROM itemTable WHERE key='storage.serviceMachineId'\"","5. Paste both values in the form below"],
            "alternativeMethod":["Or use this one-liner to get both values:","sqlite3 state.vscdb \"SELECT key, value FROM itemTable WHERE key IN ('cursorAuth/accessToken', 'storage.serviceMachineId')\""]
        },
        "requiredFields":[
            {"name":"accessToken","label":"Access Token","description":"From cursorAuth/accessToken in state.vscdb","type":"textarea"},
            {"name":"machineId","label":"Machine ID","description":"From storage.serviceMachineId in state.vscdb","type":"text"}
        ]
    })).into_response()
}

async fn api_import_cursor_token(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    let token = input
        .get("accessToken")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let machine_id = input
        .get("machineId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Access token is required"})),
        )
            .into_response();
    }
    if machine_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Machine ID is required"})),
        )
            .into_response();
    }
    if token.len() < 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid token format. Token appears too short."})),
        )
            .into_response();
    }
    let normalized_id = machine_id.replace('-', "");
    if normalized_id.len() < 32 || !normalized_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Invalid machine ID format. Expected UUID format."})),
        )
            .into_response();
    }
    let user = token.split('.').nth(1).and_then(decode_jwt_payload);
    let email = user
        .as_ref()
        .and_then(|p| p["email"].as_str().or(p["sub"].as_str()))
        .map(str::to_owned);
    let user_id = user
        .as_ref()
        .and_then(|p| p["sub"].as_str().or(p["user_id"].as_str()))
        .map(str::to_owned);
    let expires = (chrono::Utc::now() + chrono::Duration::seconds(86400))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    let specific = json!({"machineId":machine_id,"authMethod":"imported","provider":"Imported","userId":user_id});
    let data = json!({"apiKey":"","accessToken":token,"refreshToken":null,"expiresAt":expires,"providerSpecificData":specific,"testStatus":"active"});
    if let Err(error)=sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?, ?,?,1,1,?,?,?)").bind(&id).bind("cursor").bind("oauth").bind("Imported Cursor Token").bind(email.as_deref()).bind(data.to_string()).bind(&now).bind(&now).execute(&state.db).await{return ApiError::upstream(error.to_string()).into_response();}
    Json(json!({"success":true,"connection":{"id":id,"provider":"cursor","email":email}}))
        .into_response()
}

async fn api_import_kiro_api_key(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    let api_key = input
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if api_key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"API key is required"})),
        )
            .into_response();
    }
    let region = input
        .get("region")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or("us-east-1");
    let mut parts = region.split('-');
    let valid_region = parts
        .next()
        .is_some_and(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_lowercase()))
        && parts
            .next()
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase()))
        && parts
            .next()
            .is_some_and(|p| (1..=2).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none();
    if !valid_region {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"API key validation failed"})),
        )
            .into_response();
    }
    let url = format!("https://q.{region}.amazonaws.com/ListAvailableModels?origin=AI_EDITOR");
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("Authorization", format!("Bearer {api_key}")),
        ("TokenType", "API_KEY".into()),
        ("Accept", "application/json".into()),
        ("User-Agent", "AWS-SDK-JS/3.0.0 kiro-ide/1.0.0".into()),
        ("X-Amz-User-Agent", "aws-sdk-js/3.0.0 kiro-ide/1.0.0".into()),
    ] {
        if insert_header(&mut headers, name, &value).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"API key validation failed"})),
            )
                .into_response();
        }
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"API key validation failed"})),
            )
                .into_response();
        }
    };
    let response = match provider_request_headers(&client, "GET", &url, headers, None).await {
        Ok(response) => response,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"API key validation failed"})),
            )
                .into_response();
        }
    };
    if !response.status().is_success() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"API key validation failed"})),
        )
            .into_response();
    }
    let models = response
        .json::<Value>()
        .await
        .ok()
        .and_then(|data| data["models"].as_array().cloned())
        .unwrap_or_default();
    if models.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"API key validation failed"})),
        )
            .into_response();
    }
    let email = api_key
        .split('.')
        .nth(1)
        .and_then(decode_jwt_payload)
        .and_then(|payload| {
            payload["email"]
                .as_str()
                .or(payload["preferred_username"].as_str())
                .or(payload["sub"].as_str())
                .map(str::to_owned)
        });
    let expires = (chrono::Utc::now() + chrono::Duration::days(365))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let specific = json!({"region":region,"authMethod":"api_key","provider":"API Key"});
    let data = json!({"apiKey":"","accessToken":api_key,"refreshToken":null,"expiresAt":expires,"providerSpecificData":specific,"testStatus":"active"});
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    if let Err(error)=sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?, ?,?,1,1,?,?,?)").bind(&id).bind("kiro").bind("api_key").bind("Kiro API Key").bind(email.as_deref()).bind(data.to_string()).bind(&now).bind(&now).execute(&state.db).await{return ApiError::upstream(error.to_string()).into_response();}
    Json(json!({"success":true,"connection":{"id":id,"provider":"kiro","email":email}}))
        .into_response()
}

fn zed_org_id(user: &Value) -> String {
    let normalize = |value: &Value| -> Option<String> {
        if let Some(v) = value.as_str() {
            (!v.is_empty()).then(|| v.to_string())
        } else if let Some(v) = value[0].as_str() {
            Some(v.to_string())
        } else {
            value["id"].as_str().map(str::to_owned)
        }
    };
    normalize(&user["default_organization_id"])
        .or_else(|| normalize(&user["defaultOrganizationId"]))
        .or_else(|| {
            user["organizations"]
                .as_array()
                .and_then(|orgs| {
                    orgs.iter()
                        .find(|org| org["is_personal"] == true)
                        .or_else(|| orgs.first())
                })
                .and_then(normalize)
        })
        .unwrap_or_default()
}

fn dashboard_session(state: &AppState, headers: &HeaderMap) -> Option<Value> {
    let token = cookie_value(headers, "auth_token")?;
    auth::verify_dashboard_token(&state.auth_secret, token)
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|entry| entry.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn no_store_json(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn non_empty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn login_client_ip(headers: &HeaderMap, peer: std::net::SocketAddr) -> String {
    if std::env::var("TRUST_PROXY").as_deref() == Ok("true") {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}

fn is_local_request(headers: &HeaderMap, peer: std::net::SocketAddr) -> bool {
    if headers.contains_key("x-9r-via-proxy") || !peer.ip().is_loopback() {
        return false;
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let host = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(origin)
            .split('/')
            .next()
            .unwrap_or_default();
        if !matches!(
            host.split(':').next().unwrap_or_default(),
            "localhost" | "127.0.0.1" | "[::1]"
        ) {
            return false;
        }
    }
    true
}

fn is_tunnel_request(headers: &HeaderMap, settings: &Value) -> bool {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["tunnelUrl", "tailscaleUrl"].iter().any(|key| {
        settings[*key]
            .as_str()
            .filter(|value| !value.is_empty())
            .and_then(|value| {
                value
                    .split_once("://")
                    .map(|(_, rest)| rest)
                    .or(Some(value))
            })
            .map(|value| {
                value
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            })
            .is_some_and(|tunnel_host| !tunnel_host.is_empty() && tunnel_host == host)
    })
}

async fn index() -> Response {
    if std::env::var_os("NINEROUTER_STATIC_DIR").is_some() {
        return serve_static_path("/", Method::GET).await;
    }
    Html(include_str!("index.html")).into_response()
}

async fn static_fallback(
    State(state): State<AppState>,
    uri: OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let path = uri.0.path();
    if path.starts_with("/api/")
        || path == "/api"
        || path.starts_with("/v1/")
        || path == "/v1"
        || path.starts_with("/admin/")
        || path == "/admin"
        || path == "/health"
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if path == "/dashboard" || path.starts_with("/dashboard/") {
        let settings = read_settings(&state.db).await.unwrap_or_else(|_| json!({}));
        if settings["requireLogin"] != false && dashboard_session(&state, &headers).is_none() {
            return Redirect::temporary("/login/").into_response();
        }
        if settings["tunnelDashboardAccess"] == false && is_tunnel_request(&headers, &settings) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    if let Some(provider_id) = path
        .strip_prefix("/dashboard/providers/")
        .map(|provider_id| provider_id.trim_end_matches('/'))
    {
        if !provider_id.is_empty()
            && !provider_id.contains('/')
            && (provider_id.starts_with("openai-compatible-")
                || provider_id.starts_with("anthropic-compatible-"))
        {
            let query_suffix = uri
                .0
                .query()
                .map(|query| format!("&{query}"))
                .unwrap_or_default();
            let target =
                format!("/dashboard/providers/custom/?providerId={provider_id}{query_suffix}");
            return Redirect::temporary(&target).into_response();
        }
    }
    if let Some(remainder) = path.strip_prefix("/dashboard/media-providers/") {
        if let Some((kind, id)) = remainder.split_once('/') {
            let id = id.trim_end_matches('/');
            if id.starts_with("custom-embedding-") && !id.contains('/') {
                let query_suffix = uri
                    .0
                    .query()
                    .map(|query| format!("&{query}"))
                    .unwrap_or_default();
                let target = format!(
                    "/dashboard/media-providers/{kind}/custom/?providerId={id}{query_suffix}"
                );
                return Redirect::temporary(&target).into_response();
            }
        }
    }
    if let Some(combo_id) = path
        .strip_prefix("/dashboard/media-providers/combo/")
        .map(|combo_id| combo_id.trim_end_matches('/'))
    {
        if !combo_id.is_empty() && combo_id != "custom" && !combo_id.contains('/') {
            let query_suffix = uri
                .0
                .query()
                .map(|query| format!("&{query}"))
                .unwrap_or_default();
            let target = format!(
                "/dashboard/media-providers/combo/custom/?comboId={combo_id}{query_suffix}"
            );
            return Redirect::temporary(&target).into_response();
        }
    }
    serve_static_path(path, method).await
}

async fn serve_static_path(request_path: &str, method: Method) -> Response {
    if !matches!(method, Method::GET | Method::HEAD) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(root) = std::env::var_os("NINEROUTER_STATIC_DIR").map(PathBuf::from) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(root) = tokio::fs::canonicalize(root).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let relative = request_path.trim_start_matches('/');
    let candidate = root.join(relative);
    let candidate = match tokio::fs::canonicalize(&candidate).await {
        Ok(path) if path.starts_with(&root) && path.is_file() => Some(path),
        Ok(path) if path.starts_with(&root) && path.is_dir() => {
            tokio::fs::canonicalize(path.join("index.html"))
                .await
                .ok()
                .filter(|path| path.starts_with(&root) && path.is_file())
        }
        _ => None,
    };
    let candidate = if candidate.is_some() {
        candidate
    } else if !request_path.starts_with("/_next/")
        && std::path::Path::new(request_path).extension().is_none()
    {
        let page_file = root.join(format!("{relative}.html"));
        match tokio::fs::canonicalize(page_file).await {
            Ok(path) if path.starts_with(&root) && path.is_file() => Some(path),
            _ => tokio::fs::canonicalize(root.join("index.html"))
                .await
                .ok()
                .filter(|path| path.starts_with(&root) && path.is_file()),
        }
    } else {
        candidate
    };
    let Some(path) = candidate else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(file) = tokio::fs::File::open(&path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(metadata) = file.metadata().await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = static_content_type(&path);
    let mut response = Response::new(if method == Method::HEAD {
        Body::empty()
    } else {
        let stream = futures_util::stream::try_unfold(file, |mut file| async move {
            use tokio::io::AsyncReadExt;
            let mut buffer = vec![0; 64 * 1024];
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                Ok::<_, std::io::Error>(None)
            } else {
                buffer.truncate(bytes_read);
                Ok(Some((Bytes::from(buffer), file)))
            }
        });
        Body::from_stream(stream)
    });
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(value) = HeaderValue::from_str(&metadata.len().to_string()) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    let cache_control = if request_path.starts_with("/_next/static/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response
}

fn static_content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("ico") => "image/x-icon",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        Some("webp") => "image/webp",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn list_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize(&state, &headers).await?;
    let providers = store::list_providers(&state.db).await?;
    let safe: Vec<Value> = providers.into_iter().map(provider_json).collect();
    Ok(Json(json!({"providers":safe})))
}

async fn api_models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize(&state, &headers).await?;
    api_list_connections_inner(&state.db).await
}

async fn api_suggested_models(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let query: HashMap<String, String> = uri
        .query()
        .and_then(|q| serde_urlencoded::from_str(q).ok())
        .unwrap_or_default();
    let (Some(url), Some(kind)) = (query.get("url"), query.get("type")) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Missing url or type"})),
        )
            .into_response();
    };
    if !matches!(
        kind.as_str(),
        "openrouter-free"
            | "opencode-free"
            | "opencode-go"
            | "mimo-free"
            | "minimax-code"
            | "airforce-free"
            | "nous-free"
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Unknown filter type"})),
        )
            .into_response();
    }
    let response = match state
        .http
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response,
        _ => return Json(json!({"data":[]})).into_response(),
    };
    let payload = match response.json::<Value>().await {
        Ok(payload) => payload,
        Err(_) => return Json(json!({"data":[]})).into_response(),
    };
    Json(json!({"data": filter_suggested_models(&payload, kind)})).into_response()
}

async fn api_kilo_free_models(State(state): State<AppState>) -> Response {
    let cache = KILO_MODELS_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    {
        let cached = cache.lock().await;
        if let Some((updated, models)) = cached.as_ref() {
            if updated.elapsed() < Duration::from_secs(60 * 60) {
                return Json(json!({"models":models,"cached":true})).into_response();
            }
        }
    }
    let result = state
        .http
        .get("https://api.kilo.ai/api/gateway/models")
        .header(header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status);
    if let Ok(response) = result {
        if let Ok(payload) = response.json::<Value>().await {
            let models: Vec<Value> = payload["data"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|model| model["isFree"] == true)
                .map(|model| {
                    json!({
                        "id":model["id"],
                        "name":model["name"],
                        "isFree":true,
                        "context_length":model["context_length"].as_u64().unwrap_or(0),
                    })
                })
                .collect();
            let models = Value::Array(models);
            *cache.lock().await = Some((Instant::now(), models.clone()));
            return Json(json!({"models":models,"cached":false})).into_response();
        }
    }
    let cached = cache.lock().await;
    if let Some((_, models)) = cached.as_ref() {
        return Json(
            json!({"models":models,"cached":true,"warning":"Kilo model catalog request failed"}),
        )
        .into_response();
    }
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"models":[],"error":"Failed to fetch Kilo models"})),
    )
        .into_response()
}

fn filter_suggested_models(payload: &Value, kind: &str) -> Vec<Value> {
    let source = payload
        .get("data")
        .or_else(|| payload.get("models"))
        .unwrap_or(payload);
    let one = if source.is_array() {
        None
    } else {
        Some(source.clone())
    };
    let models = source
        .as_array()
        .cloned()
        .or_else(|| one.map(|v| vec![v]))
        .unwrap_or_default();
    match kind {
        "openrouter-free" | "nous-free" => {
            let mut filtered = models.into_iter().filter_map(|model| {
                let prompt = &model["pricing"]["prompt"];
                let completion = &model["pricing"]["completion"];
                let context = model["context_length"].as_u64()
                    .or_else(|| model["top_provider"]["context_length"].as_u64()).unwrap_or(0);
                let is_zero = |v: &Value| v.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| v.as_f64()) == Some(0.0);
                if context < 200_000 || !is_zero(prompt) || !is_zero(completion) { return None; }
                if model["architecture"]["output_modalities"].as_array().is_some_and(|items| !items.is_empty() && !items.iter().any(|v| v == "text")) { return None; }
                let id = model["id"].as_str()?.to_string();
                let name = model["name"].as_str().unwrap_or(&id).to_string();
                Some(json!({"id":id,"name":name,"contextLength":context}))
            }).collect::<Vec<_>>();
            filtered.sort_by(|a,b| b["contextLength"].as_u64().cmp(&a["contextLength"].as_u64()));
            if kind == "nous-free" {
                filtered.sort_by_key(|model| !model["id"].as_str().unwrap_or_default().starts_with("nousresearch/"));
            }
            filtered
        }
        "opencode-free" => models.into_iter().filter_map(|m| {
            let id = m["id"].as_str()?;
            ((id.ends_with("-free") || id == "big-pickle") && id != "deepseek-v4-flash-free")
                .then(|| json!({"id":id,"name":id}))
        }).collect(),
        "opencode-go" => models.into_iter().filter_map(|m| {
            let id = m["id"].as_str()?;
            Some(json!({"id":id,"name":id}))
        }).collect(),
        "mimo-free" => models.into_iter().filter_map(|m| {
            let id = m["id"].as_str()?;
            (id.starts_with("mimo") || m["name"].as_str().unwrap_or_default().to_ascii_lowercase().contains("mimo"))
                .then(|| json!({"id":id,"name":m["name"].as_str().unwrap_or(id)}))
        }).collect(),
        "minimax-code" => models.into_iter().find_map(|env| {
            let provider = env["providers"].as_array()?.iter().find(|p| p["providerId"] == "minimax")?;
            let entries = provider["config"]["models"].as_object()?;
            let mut out: Vec<Value> = entries.iter().filter_map(|(id,m)| {
                (!id.trim().is_empty() && m.is_object()).then(|| json!({"id":id,"name":m["name"].as_str().unwrap_or(id),"contextLength":m["limit"]["context"].as_u64()}))
            }).collect();
            out.sort_by(|a,b| b["contextLength"].as_u64().cmp(&a["contextLength"].as_u64()));
            Some(out)
        }).unwrap_or_default(),
        "airforce-free" => models.into_iter().filter_map(|m| {
            let id = m["id"].as_str()?;
            let is_free = m["tier"] == "free" || id.ends_with(":free");
            let media = m["media_type"].as_str();
            (is_free && m["supports_chat"] == true && media.is_none_or(|v| matches!(v,"chat"|"text")))
                .then(|| json!({"id":id,"name":m["name"].as_str().unwrap_or(id),"contextLength":m["context_length"]}))
        }).collect(),
        _ => Vec::new(),
    }
}

async fn api_list_connections(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    api_list_connections_inner(&s.db).await
}
async fn api_list_connections_inner(db: &SqlitePool) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let rows=sqlx::query("SELECT id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt FROM providerConnections ORDER BY COALESCE(priority,999),updatedAt").fetch_all(db).await?;
    let connections = rows
        .into_iter()
        .map(|r| {
            let mut c = serde_json::from_str::<Value>(r.get::<String, _>("data").as_str())
                .unwrap_or(json!({}));
            if !c.is_object() {
                c = json!({});
            }
            for key in ["apiKey", "accessToken", "refreshToken", "idToken"] {
                c.as_object_mut().unwrap().remove(key);
            }
            c["id"] = json!(r.get::<String, _>("id"));
            c["provider"] = json!(r.get::<String, _>("provider"));
            c["authType"] = json!(r.get::<String, _>("authType"));
            c["name"] = json!(r.get::<Option<String>, _>("name"));
            c["email"] = json!(r.get::<Option<String>, _>("email"));
            c["priority"] = json!(r.get::<Option<i64>, _>("priority"));
            c["isActive"] = json!(r.get::<i64, _>("isActive") == 1);
            c["createdAt"] = json!(r.get::<String, _>("createdAt"));
            c["updatedAt"] = json!(r.get::<String, _>("updatedAt"));
            c
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"connections":connections})))
}
async fn api_get_connection(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let all = api_list_connections_inner(&s.db).await?.0;
    let conn = all["connections"]
        .as_array()
        .and_then(|a| a.iter().find(|c| c["id"] == id))
        .cloned()
        .ok_or_else(|| ApiError::not_found("Connection not found"))?;
    Ok(Json(json!({"connection":conn})))
}

async fn api_get_provider_overrides(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let canonical = store::canonical_provider_id(&id);
    let settings = read_settings(&state.db).await?;
    let headers = settings["providerOverrides"][canonical]["headers"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    // Registry-specific built-in transport headers are not yet included in
    // rust/providers.json. Keep this field compatible with the frontend shape.
    Ok(Json(json!({"headers":headers,"builtinHeaders":{}})))
}

async fn api_get_provider_models(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    use sqlx::Row;
    let row = match sqlx::query("SELECT id,provider,data FROM providerConnections WHERE id=?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::not_found("Connection not found").into_response(),
        Err(error) => return ApiError::upstream(error.to_string()).into_response(),
    };
    let provider: String = row.try_get("provider").unwrap_or_default();
    let data: Value = serde_json::from_str(
        row.try_get::<String, _>("data")
            .unwrap_or_default()
            .as_str(),
    )
    .unwrap_or_else(|_| json!({}));
    let specific = &data["providerSpecificData"];
    let Some(mut base_url) = specific
        .get("baseUrl")
        .or_else(|| data.get("baseUrl"))
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        let message = if provider.starts_with("anthropic-compatible-") {
            "No base URL configured for Anthropic compatible provider"
        } else {
            "No base URL configured for OpenAI compatible provider"
        };
        return ApiError::bad_request(message).into_response();
    };
    let is_anthropic = provider.starts_with("anthropic-compatible-");
    if !is_anthropic && !provider.starts_with("openai-compatible-") {
        return ApiError::bad_request(format!(
            "Provider {provider} does not support models listing"
        ))
        .into_response();
    }
    while base_url.ends_with('/') {
        base_url.pop();
    }
    if is_anthropic && base_url.ends_with("/messages") {
        base_url.truncate(base_url.len() - "/messages".len());
    }
    let api_key = data["apiKey"].as_str().unwrap_or_default();
    let mut request = state
        .http
        .get(format!("{base_url}/models"))
        .header(header::CONTENT_TYPE, "application/json")
        .timeout(Duration::from_secs(15));
    if is_anthropic {
        if !api_key.is_empty() {
            request = request.header("x-api-key", api_key).bearer_auth(api_key);
        }
        request = request.header("anthropic-version", "2023-06-01");
    } else if !api_key.is_empty() {
        request = request.bearer_auth(api_key);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return ApiError::upstream(error.to_string()).into_response(),
    };
    if !response.status().is_success() {
        return ApiError::new(
            StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("Failed to fetch models: {}", response.status().as_u16()),
        )
        .into_response();
    }
    let models = match response.json::<Value>().await {
        Ok(payload) => payload
            .get("data")
            .or_else(|| payload.get("models"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Err(error) => return ApiError::upstream(error.to_string()).into_response(),
    };
    Json(json!({"provider":provider,"connectionId":id,"models":models})).into_response()
}

async fn api_put_provider_overrides(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let headers = input.get("headers");
    let normalized = normalize_provider_override_headers(headers).map_err(ApiError::bad_request)?;
    let canonical = store::canonical_provider_id(&id).to_string();
    let mut settings = read_settings(&state.db).await?;
    if !settings["providerOverrides"].is_object() {
        settings["providerOverrides"] = json!({});
    }
    if let Some(headers) = normalized.as_ref() {
        settings["providerOverrides"][&canonical] = json!({"headers":headers});
    } else if let Some(overrides) = settings["providerOverrides"].as_object_mut() {
        overrides.remove(&canonical);
    }
    sqlx::query("INSERT INTO settings(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data")
        .bind(settings.to_string())
        .execute(&state.db)
        .await?;
    Ok(Json(
        json!({"headers":normalized.unwrap_or_else(|| json!({}))}),
    ))
}

fn normalize_provider_override_headers(value: Option<&Value>) -> Result<Option<Value>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let Some(headers) = value.as_object() else {
        return Err("headers must be an object".into());
    };
    let blocked = [
        "host",
        "content-length",
        "content-type",
        "connection",
        "transfer-encoding",
        "authorization",
        "cookie",
    ];
    let entries = headers
        .iter()
        .filter(|(_, value)| !value.is_null() && value.as_str() != Some(""))
        .collect::<Vec<_>>();
    if entries.len() > 20 {
        return Err("Too many headers (max 20)".into());
    }
    let mut clean = serde_json::Map::new();
    for (name, value) in entries {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("Invalid header name: {name}"));
        }
        let Some(value) = value.as_str() else {
            return Err(format!("Invalid value for header {name}"));
        };
        if value.contains('\r') || value.contains('\n') {
            return Err(format!("Invalid value for header {name}"));
        }
        if value.len() > 8192 {
            return Err(format!("Header {name} value too long (max 8192)"));
        }
        if blocked
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
        {
            return Err(format!("Header {name} cannot be overridden"));
        }
        clean.insert(name.clone(), json!(value));
    }
    Ok((!clean.is_empty()).then_some(Value::Object(clean)))
}

async fn api_delete_connection(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let result = sqlx::query("DELETE FROM providerConnections WHERE id=?")
        .bind(id)
        .execute(&s.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Connection not found"));
    }
    Ok(Json(json!({"message":"Connection deleted successfully"})))
}

async fn api_list_provider_nodes(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id,type,name,data,createdAt,updatedAt FROM providerNodes ORDER BY createdAt",
    )
    .fetch_all(&s.db)
    .await?;
    let nodes = rows
        .into_iter()
        .map(|r| {
            let mut node = serde_json::from_str::<Value>(r.get::<String, _>("data").as_str())
                .unwrap_or(json!({}));
            if !node.is_object() {
                node = json!({});
            }
            node["id"] = json!(r.get::<String, _>("id"));
            node["type"] = json!(r.get::<Option<String>, _>("type"));
            node["name"] = json!(r.get::<Option<String>, _>("name"));
            node["createdAt"] = json!(r.get::<String, _>("createdAt"));
            node["updatedAt"] = json!(r.get::<String, _>("updatedAt"));
            node
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"nodes":nodes})))
}
async fn api_create_provider_node(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<impl IntoResponse, ApiError> {
    let name = b
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Name is required"))?;
    let prefix = b
        .get("prefix")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Prefix is required"))?;
    let kind = b
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("openai-compatible");
    if ![
        "openai-compatible",
        "anthropic-compatible",
        "custom-embedding",
    ]
    .contains(&kind)
    {
        return Err(ApiError::bad_request("Invalid provider node type"));
    }
    let api_type = b.get("apiType").and_then(Value::as_str).unwrap_or_default();
    if kind == "openai-compatible" && !["chat", "responses"].contains(&api_type) {
        return Err(ApiError::bad_request("Invalid OpenAI compatible API type"));
    }
    let (id, default_url) = match kind {
        "openai-compatible" => (
            format!(
                "openai-compatible-{api_type}-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            ),
            "https://api.openai.com/v1",
        ),
        "anthropic-compatible" => (
            format!(
                "anthropic-compatible-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            ),
            "https://api.anthropic.com/v1",
        ),
        _ => (
            format!(
                "custom-embedding-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            ),
            "https://api.openai.com/v1",
        ),
    };
    let mut base = b
        .get("baseUrl")
        .and_then(Value::as_str)
        .unwrap_or(default_url)
        .trim()
        .trim_end_matches('/')
        .to_owned();
    let suffix = if kind == "anthropic-compatible" {
        "/messages"
    } else if kind == "custom-embedding" {
        "/embeddings"
    } else {
        ""
    };
    if !suffix.is_empty() && base.ends_with(suffix) {
        base.truncate(base.len() - suffix.len());
    }
    let now = timestamp();
    let mut data = json!({"prefix":prefix,"baseUrl":base});
    if kind == "openai-compatible" {
        data["apiType"] = json!(api_type);
    }
    sqlx::query(
        "INSERT INTO providerNodes(id,type,name,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(kind)
    .bind(name)
    .bind(data.to_string())
    .bind(&now)
    .bind(&now)
    .execute(&s.db)
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"node":{"id":id,"type":kind,"name":name,"prefix":prefix,"baseUrl":base,"apiType":if kind=="openai-compatible"{Some(api_type)}else{None},"createdAt":now,"updatedAt":now}}),
        ),
    ))
}
async fn api_update_provider_node(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let row = sqlx::query("SELECT type,name,data,createdAt FROM providerNodes WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.db)
        .await?
        .ok_or_else(|| ApiError::not_found("Provider node not found"))?;
    let kind = row.get::<Option<String>, _>("type").unwrap_or_default();
    let name = b
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Name is required"))?;
    let prefix = b
        .get("prefix")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Prefix is required"))?;
    let api_type = b.get("apiType").and_then(Value::as_str).unwrap_or_default();
    if kind == "openai-compatible" && !["chat", "responses"].contains(&api_type) {
        return Err(ApiError::bad_request("Invalid OpenAI compatible API type"));
    }
    let mut base = b
        .get("baseUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Base URL is required"))?
        .trim_end_matches('/')
        .to_owned();
    let suffix = if kind == "anthropic-compatible" {
        "/messages"
    } else if kind == "custom-embedding" {
        "/embeddings"
    } else {
        ""
    };
    if !suffix.is_empty() && base.ends_with(suffix) {
        base.truncate(base.len() - suffix.len());
    }
    let mut data =
        serde_json::from_str::<Value>(row.get::<String, _>("data").as_str()).unwrap_or(json!({}));
    data["prefix"] = json!(prefix);
    data["baseUrl"] = json!(base);
    if kind == "openai-compatible" {
        data["apiType"] = json!(api_type);
    }
    let now = timestamp();
    sqlx::query("UPDATE providerNodes SET name=?,data=?,updatedAt=? WHERE id=?")
        .bind(name)
        .bind(data.to_string())
        .bind(&now)
        .bind(&id)
        .execute(&s.db)
        .await?;
    let rows = sqlx::query("SELECT id,data FROM providerConnections WHERE provider=?")
        .bind(&id)
        .fetch_all(&s.db)
        .await?;
    for conn in rows {
        let cid = conn.get::<String, _>("id");
        let mut d = serde_json::from_str::<Value>(conn.get::<String, _>("data").as_str())
            .unwrap_or(json!({}));
        d["providerSpecificData"]["prefix"] = json!(prefix);
        d["providerSpecificData"]["baseUrl"] = json!(base);
        d["providerSpecificData"]["nodeName"] = json!(name);
        if kind == "openai-compatible" {
            d["providerSpecificData"]["apiType"] = json!(api_type);
        }
        sqlx::query("UPDATE providerConnections SET data=?,updatedAt=? WHERE id=?")
            .bind(d.to_string())
            .bind(&now)
            .bind(cid)
            .execute(&s.db)
            .await?;
    }
    Ok(Json(
        json!({"node":{"id":id,"type":kind,"name":name,"prefix":prefix,"baseUrl":base,"apiType":if kind=="openai-compatible"{Some(api_type)}else{None},"createdAt":row.get::<String,_>("createdAt"),"updatedAt":now}}),
    ))
}
async fn api_delete_provider_node(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM providerNodes WHERE id=?")
        .bind(&id)
        .fetch_one(&s.db)
        .await?;
    if exists == 0 {
        return Err(ApiError::not_found("Provider node not found"));
    }
    sqlx::query("DELETE FROM providerConnections WHERE provider=?")
        .bind(&id)
        .execute(&s.db)
        .await?;
    sqlx::query("DELETE FROM providerNodes WHERE id=?")
        .bind(&id)
        .execute(&s.db)
        .await?;
    sqlx::query("DELETE FROM kv WHERE scope='customModels' AND key LIKE ?")
        .bind(format!("{id}|%"))
        .execute(&s.db)
        .await?;
    Ok(Json(json!({"success":true})))
}

async fn api_create_connection(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<impl IntoResponse, ApiError> {
    let provider = b
        .get("provider")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Invalid provider"))?;
    let auth = b
        .get("authType")
        .and_then(Value::as_str)
        .unwrap_or("apikey");
    let api_key = b.get("apiKey").and_then(Value::as_str).unwrap_or_default();
    if auth == "apikey" && api_key.is_empty() && provider != "ollama-local" {
        return Err(ApiError::bad_request("API Key is required"));
    }
    let name = b
        .get("name")
        .or_else(|| b.get("displayName"))
        .and_then(Value::as_str)
        .unwrap_or(provider);
    let explicit_id = b.get("id").and_then(Value::as_str);
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM providerConnections WHERE provider=? AND authType=? AND name=?",
    )
    .bind(provider)
    .bind(auth)
    .bind(name)
    .fetch_one(&s.db)
    .await?;
    if explicit_id.is_none()
        && exists > 0
        && b.get("allowOverwrite").and_then(Value::as_bool) != Some(true)
        && b.get("overwrite").and_then(Value::as_bool) != Some(true)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Connection with this name already exists",
        ));
    }
    let id = explicit_id
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let now = timestamp();
    let mut data = serde_json::Map::new();
    for (key, val) in b.as_object().into_iter().flatten() {
        if ![
            "id",
            "provider",
            "authType",
            "name",
            "displayName",
            "email",
            "priority",
            "isActive",
            "apiKey",
            "allowOverwrite",
            "overwrite",
        ]
        .contains(&key.as_str())
        {
            data.insert(key.clone(), val.clone());
        }
    }
    data.insert("apiKey".into(), json!(api_key));
    let email = b.get("email").and_then(Value::as_str);
    let priority = b.get("priority").and_then(Value::as_i64).unwrap_or(1);
    let active = b.get("isActive").and_then(Value::as_bool).unwrap_or(true);
    sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,authType=excluded.authType,name=excluded.name,email=excluded.email,priority=excluded.priority,isActive=excluded.isActive,data=excluded.data,updatedAt=excluded.updatedAt")
      .bind(&id).bind(provider).bind(auth).bind(name).bind(email).bind(priority).bind(if active{1}else{0}).bind(Value::Object(data).to_string()).bind(&now).bind(&now).execute(&s.db).await?;
    let conn = api_list_connections_inner(&s.db).await?.0["connections"]
        .as_array()
        .and_then(|a| a.iter().find(|c| c["id"] == id))
        .cloned()
        .unwrap_or(Value::Null);
    Ok((
        if exists > 0 {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({"connection":conn})),
    ))
}

async fn api_update_connection(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let row =
        sqlx::query("SELECT name,email,priority,isActive,data FROM providerConnections WHERE id=?")
            .bind(&id)
            .fetch_optional(&s.db)
            .await?
            .ok_or_else(|| ApiError::not_found("Connection not found"))?;
    let mut data =
        serde_json::from_str::<Value>(row.get::<String, _>("data").as_str()).unwrap_or(json!({}));
    let mut name = row.get::<Option<String>, _>("name");
    let mut email = row.get::<Option<String>, _>("email");
    let mut priority = row.get::<Option<i64>, _>("priority");
    let mut active = row.get::<i64, _>("isActive");
    if let Some(v) = b.get("name") {
        name = v.as_str().map(str::to_owned);
    }
    if let Some(v) = b.get("email") {
        email = v.as_str().map(str::to_owned);
    }
    if let Some(v) = b.get("priority") {
        priority = v.as_i64();
    }
    if let Some(v) = b.get("isActive") {
        active = if v.as_bool() == Some(false) { 0 } else { 1 };
    }
    if let Some(obj) = b.as_object() {
        for (k, v) in obj {
            match k.as_str() {
                "apiKey" if v.as_str().is_some_and(|x| !x.is_empty()) => data["apiKey"] = v.clone(),
                "providerSpecificData" => {
                    let mut psd = data
                        .get("providerSpecificData")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default();
                    if let Some(new) = v.as_object() {
                        psd.extend(new.clone());
                    }
                    data["providerSpecificData"] = Value::Object(psd);
                }
                "globalPriority" | "defaultModel" | "testStatus" | "lastError" | "lastErrorAt" => {
                    data[k] = v.clone()
                }
                _ => (),
            }
        }
    }
    sqlx::query("UPDATE providerConnections SET name=?,email=?,priority=?,isActive=?,data=?,updatedAt=? WHERE id=?").bind(name).bind(email).bind(priority).bind(active).bind(data.to_string()).bind(timestamp()).bind(&id).execute(&s.db).await?;
    let conn = api_list_connections_inner(&s.db).await?.0["connections"]
        .as_array()
        .and_then(|a| a.iter().find(|c| c["id"] == id))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Json(json!({"connection":conn})))
}
async fn api_dashboard_models(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let aliases = kv_map(&s.db, "modelAliases").await?;
    let disabled = kv_map(&s.db, "disabledModels").await?;
    let synced_catalog = tokio::fs::read(catalog_file_path())
        .await
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .unwrap_or_default();
    let catalog: Vec<Value> = serde_json::from_str(include_str!("model_catalog.json"))
        .map_err(|error| ApiError::upstream(format!("Invalid built-in model catalog: {error}")))?;
    let mut models = Vec::with_capacity(catalog.len());
    let mut seen_full = std::collections::HashSet::new();
    let mut seen_routed = std::collections::HashSet::new();
    for mut model in catalog {
        let provider = model["provider"].as_str().unwrap_or_default().to_string();
        let provider_alias = model["providerAlias"]
            .as_str()
            .unwrap_or(&provider)
            .to_string();
        let model_id = model["model"].as_str().unwrap_or_default().to_string();
        let disabled_ids = disabled
            .get(&provider_alias)
            .or_else(|| disabled.get(&provider))
            .and_then(Value::as_array);
        if disabled_ids.is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(&model_id))) {
            continue;
        }
        let full_model = model["fullModel"].as_str().unwrap_or_default().to_string();
        let routed_model = model["routedModel"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let alias = aliases
            .get(&full_model)
            .and_then(Value::as_str)
            .unwrap_or(&model_id)
            .to_string();
        model["alias"] = json!(alias);
        let capability_key = format!("{}:{}", provider_alias, base_catalog_model_id(&model_id));
        if let Some(modalities) = synced_catalog["models"]
            .get(&capability_key)
            .and_then(Value::as_object)
        {
            for (key, value) in modalities {
                if value == true {
                    if let Some(caps) = model["caps"].as_object_mut() {
                        caps.insert(key.clone(), json!(true));
                    }
                }
            }
        }
        if let Some(limits) = synced_catalog["providers"]
            .get(provider)
            .and_then(|p| p.get(model_id))
            .and_then(Value::as_object)
        {
            if let Some(caps) = model["caps"].as_object_mut() {
                for (key, value) in limits {
                    caps.insert(key.clone(), value.clone());
                }
            }
        }
        seen_full.insert(full_model);
        seen_routed.insert(routed_model);
        models.push(model);
    }

    for custom in kv_map(&s.db, "customModels").await?.into_values() {
        if custom["type"].as_str().unwrap_or("llm") != "llm" {
            continue;
        }
        let (Some(provider_alias), Some(model_id)) =
            (custom["providerAlias"].as_str(), custom["id"].as_str())
        else {
            continue;
        };
        let full_model = format!("{provider_alias}/{model_id}");
        if seen_full.contains(&full_model) || seen_routed.contains(&full_model) {
            continue;
        }
        let mut caps = json!({"vision":false,"search":false,"reasoning":false,"contextWindow":null,"maxOutput":null});
        if let (Some(target), Some(custom_caps)) =
            (caps.as_object_mut(), custom["caps"].as_object())
        {
            target.extend(custom_caps.clone());
        }
        models.push(json!({
            "provider":provider_alias,
            "model":model_id,
            "name":custom["name"].as_str().unwrap_or(model_id),
            "fullModel":full_model,
            "routedModel":full_model,
            "alias":aliases.get(&full_model).and_then(Value::as_str).unwrap_or(model_id),
            "caps":caps,
        }));
    }
    Ok(Json(json!({"models":models})))
}

async fn api_model_availability(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT id,provider,name,email,data FROM providerConnections")
        .fetch_all(&state.db)
        .await?;
    let now = chrono::Utc::now();
    let mut models = Vec::new();
    for row in rows {
        let data: Value = serde_json::from_str(row.try_get::<String, _>("data")?.as_str())
            .unwrap_or_else(|_| json!({}));
        let locks = data.as_object().into_iter().flat_map(|object| object.iter())
            .filter_map(|(key, value)| {
                if !key.starts_with("modelLock_") || value.as_bool() == Some(false) || value.is_null() {
                    return None;
                }
                let until = value.as_str()?;
                let active = chrono::DateTime::parse_from_rfc3339(until)
                    .map(|date| date.with_timezone(&chrono::Utc) > now)
                    .unwrap_or(false);
                active.then(|| json!({"model":key.trim_start_matches("modelLock_").to_string(),"until":until}))
            })
            .collect::<Vec<_>>();
        let connection_id: String = row.try_get("id")?;
        let provider: String = row.try_get("provider")?;
        let connection_name = row
            .try_get::<Option<String>, _>("name")?
            .or(row.try_get::<Option<String>, _>("email")?)
            .unwrap_or_else(|| connection_id.clone());
        for lock in &locks {
            models.push(json!({
                "provider":provider,
                "model":lock["model"],
                "status":"cooldown",
                "until":lock["until"],
                "connectionId":connection_id,
                "connectionName":connection_name,
                "lastError":data["lastError"],
            }));
        }
        if locks.is_empty() && data["testStatus"] == "unavailable" {
            models.push(json!({
                "provider":provider,
                "model":"__all",
                "status":"unavailable",
                "connectionId":connection_id,
                "connectionName":connection_name,
                "lastError":data["lastError"],
            }));
        }
    }
    let count = models.len();
    Ok(Json(json!({"models":models,"unavailableCount":count})))
}

async fn api_test_model(State(state): State<AppState>, Json(input): Json<Value>) -> Response {
    let Some(model) = input["model"]
        .as_str()
        .filter(|model| !model.trim().is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"error":"Model required"})),
        )
            .into_response();
    };
    let kind = input["kind"].as_str().unwrap_or("llm");
    let (path, payload, expected_key) = match kind {
        "embedding" => (
            "/api/v1/embeddings",
            json!({"model":model,"input":"test"}),
            "data",
        ),
        "llm" | "chat" => (
            "/api/v1/chat/completions",
            json!({"model":model,"max_tokens":1024,"stream":false,"messages":[{"role":"user","content":"hi"}]}),
            "choices",
        ),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"ok":false,"error":format!("Model test kind '{kind}' is not implemented in Rust yet")}))).into_response(),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let key = sqlx::query_scalar::<_, String>("SELECT key FROM apiKeys WHERE isActive=1 AND accessRestricted=0 ORDER BY createdAt LIMIT 1")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .or_else(|| state.api_key.clone());
    if let Some(key) = key
        .as_deref()
        .and_then(|key| HeaderValue::from_str(&format!("Bearer {key}")).ok())
    {
        headers.insert(header::AUTHORIZATION, key);
    }
    let uri = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return ApiError::upstream("Invalid internal model test path").into_response(),
    };
    let route_path = path.trim_start_matches("/api/v1/").to_string();
    let started = Instant::now();
    let response = match proxy(
        State(state),
        OriginalUri(uri),
        Path(route_path),
        Method::POST,
        headers,
        Body::from(payload.to_string()),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return error.into_response(),
    };
    let latency_ms = started.elapsed().as_millis();
    let status = response.status();
    let raw = match to_bytes(response.into_body(), 4 * 1024 * 1024).await {
        Ok(body) => body,
        Err(error) => return ApiError::upstream(error.to_string()).into_response(),
    };
    let parsed: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = parsed["error"]["message"]
            .as_str()
            .or_else(|| parsed["error"].as_str())
            .or_else(|| parsed["message"].as_str())
            .or_else(|| std::str::from_utf8(&raw).ok())
            .unwrap_or_default();
        return Json(json!({"ok":false,"latencyMs":latency_ms,"status":status.as_u16(),"error":format!("HTTP {}: {}",status.as_u16(),detail.chars().take(240).collect::<String>())})).into_response();
    }
    let valid = if expected_key == "data" {
        parsed["data"].as_array().is_some_and(|data| {
            data.first()
                .is_some_and(|item| item["embedding"].as_array().is_some())
        })
    } else {
        parsed["choices"]
            .as_array()
            .is_some_and(|choices| !choices.is_empty())
    };
    if valid {
        Json(json!({"ok":true,"latencyMs":latency_ms,"error":null,"status":status.as_u16()}))
            .into_response()
    } else {
        let error = if expected_key == "data" {
            "Provider returned no embedding data"
        } else {
            "Provider returned no completion choices for this model"
        };
        Json(json!({"ok":false,"latencyMs":latency_ms,"status":status.as_u16(),"error":error}))
            .into_response()
    }
}

fn catalog_sync_state() -> &'static tokio::sync::Mutex<CatalogSyncState> {
    CATALOG_SYNC_STATE.get_or_init(|| tokio::sync::Mutex::new(CatalogSyncState::default()))
}

fn catalog_file_path() -> PathBuf {
    let data_dir = std::env::var_os("DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".9router")))
        .unwrap_or_else(|| PathBuf::from("./data"));
    data_dir.join("model-catalog.json")
}

fn catalog_raw_file_path() -> PathBuf {
    let mut path = catalog_file_path();
    path.set_file_name("model-catalog-raw.json");
    path
}

async fn restore_catalog_sync_state() {
    let mut state = catalog_sync_state().lock().await;
    if state.last_sync.is_some() {
        return;
    }
    let file = catalog_file_path();
    if let Ok(raw) = tokio::fs::read(&file).await {
        if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
            state.etag = value["etag"].as_str().map(str::to_owned);
            state.file_version = value["v"].as_u64();
            let modified = tokio::fs::metadata(&file)
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64);
            state.last_sync = value["syncedAt"].as_i64().or(modified);
        }
    }
}

async fn api_catalog_sync_status() -> Response {
    restore_catalog_sync_state().await;
    let state = catalog_sync_state().lock().await;
    let file = catalog_file_path();
    let catalog = match tokio::fs::read(&file).await {
        Ok(raw) => serde_json::from_slice::<Value>(&raw).ok().map(|value| {
            json!({
                "syncedAt":value["syncedAt"],
                "models":value["models"].as_object().map(serde_json::Map::len).unwrap_or(0),
                "providers":value["providers"].as_object().map(serde_json::Map::len).unwrap_or(0),
                "bytes":raw.len(),
            })
        }),
        Err(_) => None,
    };
    Json(json!({"running":state.running,"lastSync":state.last_sync,"lastError":state.last_error,"lastResult":state.last_result,"etag":state.etag,"fileVersion":state.file_version,"file":file.to_string_lossy(),"url":"https://models.dev/api.json","intervalMs":86400000,"catalog":catalog})).into_response()
}

async fn api_catalog_sync_now(State(state): State<AppState>) -> Response {
    restore_catalog_sync_state().await;
    {
        let mut current = catalog_sync_state().lock().await;
        if current.running {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"sync in progress"})),
            )
                .into_response();
        }
        current.running = true;
    }
    match sync_model_catalog(&state.http).await {
        Ok(result) => {
            let mut current = catalog_sync_state().lock().await;
            current.running = false;
            current.last_sync = Some(chrono::Utc::now().timestamp_millis());
            current.last_error = None;
            current.last_result = Some(result.clone());
            if result["status"] == "updated" {
                current.etag = result["etag"].as_str().map(str::to_owned);
                current.file_version = Some(2);
            }
            Json(json!({"success":true,"result":result})).into_response()
        }
        Err(error) => {
            let mut current = catalog_sync_state().lock().await;
            current.running = false;
            current.last_error = Some(error.clone());
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":error})),
            )
                .into_response()
        }
    }
}

pub async fn catalog_sync_scheduler() {
    if std::env::var("MODEL_CATALOG_SYNC").is_ok_and(|value| value.eq_ignore_ascii_case("off")) {
        return;
    }
    restore_catalog_sync_state().await;
    tokio::time::sleep(Duration::from_secs(60)).await;
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!("model catalog sync disabled: {error}");
            return;
        }
    };
    loop {
        let running = {
            let mut state = catalog_sync_state().lock().await;
            if state.running {
                true
            } else {
                state.running = true;
                false
            }
        };
        if !running {
            match sync_model_catalog(&client).await {
                Ok(result) => {
                    let mut state = catalog_sync_state().lock().await;
                    state.running = false;
                    state.last_sync = Some(chrono::Utc::now().timestamp_millis());
                    state.last_error = None;
                    state.last_result = Some(result.clone());
                    if result["status"] == "updated" {
                        state.etag = result["etag"].as_str().map(str::to_owned);
                        state.file_version = Some(2);
                    }
                }
                Err(error) => {
                    let mut state = catalog_sync_state().lock().await;
                    state.running = false;
                    state.last_error = Some(error);
                }
            }
        }
        let failed = catalog_sync_state().lock().await.last_error.is_some();
        tokio::time::sleep(Duration::from_secs(if failed { 1800 } else { 86400 })).await;
    }
}

async fn sync_model_catalog(client: &reqwest::Client) -> Result<Value, String> {
    restore_catalog_sync_state().await;
    let (etag, version) = {
        let state = catalog_sync_state().lock().await;
        (state.etag.clone(), state.file_version)
    };
    let mut request = client
        .get("https://models.dev/api.json")
        .header(header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(60));
    if version == Some(2) {
        if let Some(etag) = etag.as_deref() {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    if response.status() == StatusCode::NOT_MODIFIED {
        return Ok(json!({"status":"unchanged"}));
    }
    let response = response
        .error_for_status()
        .map_err(|error| error.to_string())?;
    let new_etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let upstream: Value = response.json().await.map_err(|error| error.to_string())?;
    let entries: Vec<Value> = serde_json::from_str(include_str!("model_catalog.json"))
        .map_err(|error| error.to_string())?;
    let (models, providers) = build_model_catalog_delta(&upstream, &entries);
    let synced_at = chrono::Utc::now().timestamp_millis();
    let serialized =
        json!({"v":2,"etag":new_etag,"syncedAt":synced_at,"models":models,"providers":providers});
    let catalog_file = catalog_file_path();
    let data_dir = catalog_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("./data"));
    tokio::fs::create_dir_all(data_dir)
        .await
        .map_err(|error| error.to_string())?;
    write_catalog_atomic(&catalog_file, serialized.to_string().as_bytes()).await?;
    let slim = slim_model_catalog(&upstream);
    write_catalog_atomic(&catalog_raw_file_path(), slim.to_string().as_bytes()).await?;
    Ok(
        json!({"status":"updated","etag":new_etag,"bytes":serialized.to_string().len(),"models":models.as_object().map(serde_json::Map::len).unwrap_or(0),"providers":providers.as_object().map(serde_json::Map::len).unwrap_or(0)}),
    )
}

async fn write_catalog_atomic(path: &std::path::Path, contents: &[u8]) -> Result<(), String> {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    tokio::fs::write(&temporary, contents)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::rename(&temporary, path)
        .await
        .map_err(|error| error.to_string())
}

fn upstream_provider_id(provider: &str) -> &str {
    match provider {
        "github" => "github-copilot",
        "glm" => "zai",
        "glm-cn" => "zhipuai",
        "claude" => "anthropic",
        "gemini" => "google",
        "kimi" => "moonshotai",
        "kimi-cn" => "moonshotai-cn",
        "qwen" => "alibaba",
        "qwen-cn" => "alibaba-cn",
        "zhipu" => "zhipuai",
        "hunyuan" => "tencent",
        "doubao" => "volcengine",
        "cloudflare-ai" => "cloudflare-workers-ai",
        _ => provider,
    }
}

fn base_catalog_model_id(model: &str) -> String {
    model
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .split(':')
        .next()
        .unwrap_or(model)
        .to_ascii_lowercase()
}

fn build_model_catalog_delta(upstream: &Value, entries: &[Value]) -> (Value, Value) {
    let mut local_ids: HashMap<String, Vec<String>> = HashMap::new();
    for entry in entries {
        if let Some(provider) = entry["provider"].as_str() {
            let canonical = entry["providerId"].as_str().unwrap_or(provider);
            local_ids
                .entry(upstream_provider_id(canonical).into())
                .or_default()
                .push(provider.into());
        }
    }
    for ids in local_ids.values_mut() {
        ids.sort();
        ids.dedup();
    }
    let mut models = serde_json::Map::new();
    let mut upstream_by_provider: HashMap<String, HashMap<String, Value>> = HashMap::new();
    if let Some(providers) = upstream.as_object() {
        for (provider_id, provider) in providers {
            let empty = serde_json::Map::new();
            let source = provider["models"].as_object().unwrap_or(&empty);
            let local = local_ids
                .get(provider_id)
                .cloned()
                .unwrap_or_else(|| vec![provider_id.clone()]);
            let mut by_id = HashMap::new();
            let mut seen = std::collections::HashSet::new();
            for (model_id, model) in source {
                let id = base_catalog_model_id(model_id);
                by_id.insert(id.clone(), model.clone());
                if !seen.insert(id.clone()) {
                    continue;
                }
                let mut declared = serde_json::Map::new();
                for modality in model["modalities"]["input"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    let target = match modality {
                        "image" => Some("vision"),
                        "pdf" => Some("pdf"),
                        "audio" => Some("audioInput"),
                        "video" => Some("videoInput"),
                        _ => None,
                    };
                    if let Some(key) = target {
                        declared.insert(key.into(), json!(true));
                    }
                }
                if !declared.is_empty() {
                    for local_id in &local {
                        models.insert(format!("{local_id}:{id}"), Value::Object(declared.clone()));
                    }
                    if !local.iter().any(|local_id| local_id == provider_id) {
                        models.insert(format!("{provider_id}:{id}"), Value::Object(declared));
                    }
                }
            }
            upstream_by_provider.insert(provider_id.clone(), by_id);
        }
    }
    // The table above is deliberately generated from provider/model pairs so aliases
    // retain the upstream gateway's own modality declaration.
    let mut limits = serde_json::Map::new();
    for entry in entries {
        let Some(provider) = entry["provider"].as_str() else {
            continue;
        };
        let Some(model) = entry["model"].as_str() else {
            continue;
        };
        let canonical = entry["providerId"].as_str().unwrap_or(provider);
        let upstream_id = upstream_provider_id(canonical);
        let Some(source) = upstream_by_provider.get(upstream_id) else {
            continue;
        };
        let Some(remote) = source.get(&base_catalog_model_id(model)) else {
            continue;
        };
        let mut delta = serde_json::Map::new();
        let remote_context = remote["limit"]["context"].as_f64().unwrap_or(0.0);
        let remote_output = remote["limit"]["output"].as_f64().unwrap_or(0.0);
        let current_context = entry["caps"]["contextWindow"].as_f64().unwrap_or(0.0);
        let current_output = entry["caps"]["maxOutput"].as_f64().unwrap_or(0.0);
        if remote_context > 0.0
            && entry["contextLength"].as_f64().unwrap_or(0.0) == 0.0
            && current_context > 0.0
            && (remote_context - current_context).abs() / current_context > 0.1
        {
            delta.insert("contextWindow".into(), json!(remote_context as u64));
        }
        if remote_output > 0.0
            && current_output > 0.0
            && (remote_output - current_output).abs() / current_output > 0.1
        {
            delta.insert("maxOutput".into(), json!(remote_output as u64));
        }
        if !delta.is_empty() {
            let provider_entry = limits.entry(provider).or_insert_with(|| json!({}));
            if let Some(object) = provider_entry.as_object_mut() {
                object.insert(model.into(), Value::Object(delta));
            }
        }
    }
    (Value::Object(models), Value::Object(limits))
}

fn slim_model_catalog(upstream: &Value) -> Value {
    let mut result = serde_json::Map::new();
    if let Some(providers) = upstream.as_object() {
        for (provider_id, provider) in providers {
            let mut models = serde_json::Map::new();
            if let Some(entries) = provider["models"].as_object() {
                for (id, model) in entries {
                    let mut value = serde_json::Map::new();
                    value.insert(
                        "i".into(),
                        json!(
                            model["modalities"]["input"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter(|m| m.as_str() != Some("text"))
                                .cloned()
                                .collect::<Vec<_>>()
                        ),
                    );
                    if !model["limit"]["context"].is_null() {
                        value.insert("c".into(), model["limit"]["context"].clone());
                    }
                    if !model["limit"]["output"].is_null() {
                        value.insert("o".into(), model["limit"]["output"].clone());
                    }
                    if model["reasoning"] == true {
                        value.insert("r".into(), model["reasoning"].clone());
                    }
                    models.insert(id.clone(), Value::Object(value));
                }
            }
            result.insert(provider_id.clone(), Value::Object(models));
        }
    }
    Value::Object(result)
}

async fn api_test_provider_connection(
    State(state): State<AppState>,
    Path(connection_id): Path<String>,
) -> Response {
    use sqlx::Row;
    let provider = match sqlx::query("SELECT provider FROM providerConnections WHERE id=?")
        .bind(&connection_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row.try_get::<String, _>("provider").unwrap_or_default(),
        Ok(None) => return ApiError::not_found("Connection not found").into_response(),
        Err(error) => return ApiError::upstream(error.to_string()).into_response(),
    };
    let catalog: Vec<Value> =
        serde_json::from_str(include_str!("model_catalog.json")).unwrap_or_default();
    let model = catalog.iter().find(|model| {
        model["provider"].as_str() == Some(&provider)
            || model["providerAlias"].as_str() == Some(&provider)
    });
    let (model_id, kind) = if let Some(model) = model {
        (
            model["model"].as_str().unwrap_or_default().to_string(),
            model["kind"].as_str().unwrap_or("llm").to_string(),
        )
    } else if provider.starts_with("openai-compatible-")
        || provider.starts_with("anthropic-compatible-")
    {
        let response =
            api_get_provider_models(State(state.clone()), Path(connection_id.clone())).await;
        if !response.status().is_success() {
            return Json(
                json!({"valid":false,"error":"Failed to fetch provider models","refreshed":false}),
            )
            .into_response();
        }
        let Ok(body) = to_bytes(response.into_body(), 4 * 1024 * 1024).await else {
            return ApiError::upstream("Failed to read provider model list").into_response();
        };
        let parsed = serde_json::from_slice::<Value>(&body).unwrap_or_default();
        let Some(first) = parsed["models"]
            .as_array()
            .and_then(|models| models.first())
        else {
            return Json(json!({"valid":false,"error":"No models configured for this provider","refreshed":false})).into_response();
        };
        (
            first["id"]
                .as_str()
                .or_else(|| first["name"].as_str())
                .unwrap_or_default()
                .to_string(),
            "llm".to_string(),
        )
    } else {
        return Json(json!({"valid":false,"error":"Provider does not have a Rust model test adapter yet","refreshed":false})).into_response();
    };
    let response = api_test_model(
        State(state),
        Json(json!({"model":format!("{provider}/{model_id}"),"kind":kind})),
    )
    .await;
    let parsed = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .ok()
        .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
        .unwrap_or_else(|| json!({"ok":false,"error":"Failed to read model test result"}));
    Json(json!({
        "valid":parsed["ok"] == true,
        "error":parsed["error"],
        "refreshed":false,
    }))
    .into_response()
}

async fn api_test_provider_models(
    State(state): State<AppState>,
    Path(connection_id): Path<String>,
) -> Response {
    use sqlx::Row;
    let connection = match sqlx::query("SELECT provider FROM providerConnections WHERE id=?")
        .bind(&connection_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row.try_get::<String, _>("provider").unwrap_or_default(),
        Ok(None) => return ApiError::not_found("Connection not found").into_response(),
        Err(error) => return ApiError::upstream(error.to_string()).into_response(),
    };
    let catalog: Vec<Value> =
        serde_json::from_str(include_str!("model_catalog.json")).unwrap_or_default();
    let mut models: Vec<Value> = catalog
        .into_iter()
        .filter(|model| {
            model["provider"].as_str() == Some(&connection)
                || model["providerAlias"].as_str() == Some(&connection)
        })
        .map(|model| {
            json!({"id":model["model"],"name":model["name"],"kind":model["kind"].as_str().unwrap_or("llm")})
        })
        .collect();

    if models.is_empty()
        && (connection.starts_with("openai-compatible-")
            || connection.starts_with("anthropic-compatible-"))
    {
        let response =
            api_get_provider_models(State(state.clone()), Path(connection_id.clone())).await;
        if response.status().is_success() {
            if let Ok(body) = to_bytes(response.into_body(), 4 * 1024 * 1024).await {
                if let Ok(payload) = serde_json::from_slice::<Value>(&body) {
                    models = payload["models"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|model| {
                            let id = model["id"].as_str().or_else(|| model["name"].as_str())?;
                            Some(json!({"id":id,"name":model["name"].as_str().unwrap_or(id),"kind":"llm"}))
                        })
                        .collect();
                }
            }
        }
    }
    if models.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"No models configured for this provider"})),
        )
            .into_response();
    }

    let results = futures_util::stream::iter(models.into_iter().map(|model| {
        let state = state.clone();
        let connection = connection.clone();
        async move {
            let id = model["id"].as_str().unwrap_or_default().to_string();
            let name = model["name"].as_str().unwrap_or(&id).to_string();
            let kind = model["kind"].as_str().unwrap_or("llm").to_string();
            let response = api_test_model(
                State(state),
                Json(json!({"model":format!("{connection}/{id}"),"kind":kind})),
            )
            .await;
            let response_status = response.status();
            let result = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .ok()
                .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
                .unwrap_or_else(|| json!({"ok":false,"error":"Failed to read model test result"}));
            json!({
                "modelId":id,
                "name":name,
                "ok":result["ok"] == true,
                "latencyMs":result["latencyMs"].as_u64().unwrap_or(0),
                "error":result["error"],
                "status":result["status"].as_u64().unwrap_or(response_status.as_u16() as u64),
            })
        }
    }))
    .buffer_unordered(4)
    .collect::<Vec<_>>()
    .await;
    Json(json!({"provider":connection,"connectionId":connection_id,"results":results}))
        .into_response()
}

async fn api_validate_provider_node(
    State(_state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Response {
    let Some(base_url) = input
        .get("baseUrl")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Base URL and API key required"})),
        )
            .into_response();
    };
    let Some(api_key) = input
        .get("apiKey")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Base URL and API key required"})),
        )
            .into_response();
    };
    let parsed = match reqwest::Url::parse(base_url) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => url,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"Invalid URL format"})),
            )
                .into_response();
        }
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"URL not allowed"})),
        )
            .into_response();
    }
    let local = is_local_request(&headers, peer);
    if !local && !provider_url_is_public(&parsed).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"URL not allowed"})),
        )
            .into_response();
    }
    let base = base_url.trim_end_matches('/');
    let kind = input
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let model = input
        .get("modelId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"valid":false,"error":error.to_string()})),
            )
                .into_response();
        }
    };
    if kind == "custom-embedding" {
        if model.is_empty() {
            return Json(
                json!({"valid":false,"error":"Model ID required for embedding validation"}),
            )
            .into_response();
        }
        let response = http
            .post(format!("{base}/embeddings"))
            .bearer_auth(api_key)
            .json(&json!({"model":model,"input":"ping"}))
            .send()
            .await;
        return match response {
            Ok(response) if response.status().is_success() => {
                let payload = response.json::<Value>().await.unwrap_or(Value::Null);
                let dims = payload["data"][0]["embedding"].as_array().map(Vec::len);
                Json(json!({"valid":true,"method":"embeddings","dimensions":dims})).into_response()
            }
            Ok(response) if matches!(response.status().as_u16(), 401 | 403) => {
                Json(json!({"valid":false,"error":"API key unauthorized"})).into_response()
            }
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                Json(json!({"valid":false,"error":format!("Embeddings request failed ({status}){}",if body.is_empty(){String::new()}else{format!(": {}",body.chars().take(200).collect::<String>())}),"method":"embeddings"})).into_response()
            }
            Err(error) => provider_validation_error(error),
        };
    }
    let anthropic = kind == "anthropic-compatible";
    let normalized = if anthropic && base.ends_with("/messages") {
        &base[..base.len() - 9]
    } else {
        base
    };
    let models_url = format!("{normalized}/models");
    let mut request = http.get(models_url).bearer_auth(api_key);
    if anthropic {
        request = request
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01");
    }
    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => return provider_validation_error(e),
    };
    if response.status().is_success() {
        return Json(json!({"valid":true})).into_response();
    }
    let status = response.status().as_u16();
    if matches!(status, 401 | 403) {
        return Json(json!({"valid":false,"error":"API key unauthorized"})).into_response();
    }
    if !model.is_empty() {
        let mut request=http.post(format!("{normalized}/chat/completions"))
            .bearer_auth(api_key).json(&json!({"model":model,"messages":[{"role":"user","content":"ping"}],"max_tokens":1}));
        if anthropic {
            request = request
                .header("x-api-key", api_key)
                .header("anthropic-version", "2023-06-01");
        }
        return match request.send().await {
            Ok(response) if response.status().is_success() => {
                Json(json!({"valid":true,"method":"chat"})).into_response()
            }
            Ok(response) => {
                let status = response.status().as_u16();
                Json(json!({"valid":false,"error":provider_chat_error(status),"method":"chat"}))
                    .into_response()
            }
            Err(error) => provider_validation_error(error),
        };
    }
    Json(json!({"valid":false,"error":provider_models_error(status)})).into_response()
}

async fn api_validate_provider_key(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    let mut provider = input
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if provider.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Provider and API key required"})),
        )
            .into_response();
    }
    let metadata: Value =
        serde_json::from_str(include_str!("provider_metadata.json")).unwrap_or_default();
    if metadata.get(&provider).is_none() {
        let slug = provider
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>();
        provider = slug.trim_matches('-').to_string();
    }
    if metadata.get(&provider).is_none() {
        let requested = provider
            .to_ascii_lowercase()
            .replace('_', " ")
            .replace('-', " ");
        if let Some((id, _)) = metadata.as_object().and_then(|entries| {
            entries.iter().find(|(_, entry)| {
                entry["name"]
                    .as_str()
                    .is_some_and(|name| name.to_ascii_lowercase() == requested)
            })
        }) {
            provider = id.clone();
        }
    }
    let Some(meta) = metadata.get(&provider) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Provider validation not supported"})),
        )
            .into_response();
    };
    let api_key = input
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let specific = &input["providerSpecificData"];
    let key_substitute = meta["apiKeyOptionalWith"].as_str().is_some_and(|field| {
        specific
            .get(field)
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    });
    if api_key.is_empty() && provider != "ollama-local" && meta["noAuth"] != true && !key_substitute
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Provider and API key required"})),
        )
            .into_response();
    }
    if meta["noAuth"] == true || meta["probe"]["noAuth"] == true {
        return Json(json!({"valid":true,"error":null})).into_response();
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":e.to_string()})),
            )
                .into_response();
        }
    };
    let result = validate_provider_key(&state, &client, &provider, api_key, specific, meta).await;
    match result {
        Ok(valid) => {
            Json(json!({"valid":valid,"error":if valid{Value::Null}else{json!("Invalid API key")}}))
                .into_response()
        }
        Err((status, message)) => {
            (status, Json(json!({"valid":false,"error":message}))).into_response()
        }
    }
}

async fn validate_provider_key(
    state: &AppState,
    client: &reqwest::Client,
    provider: &str,
    api_key: &str,
    specific: &Value,
    meta: &Value,
) -> Result<bool, (StatusCode, String)> {
    let probe = &meta["probe"];
    let default_model = provider_default_model(provider);
    if provider == "ollama-local" {
        let base = specific["baseUrl"]
            .as_str()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or("http://localhost:11434")
            .trim_end_matches('/');
        let mut headers = HeaderMap::new();
        if !api_key.is_empty() {
            insert_header(&mut headers, "Authorization", &format!("Bearer {api_key}"))?;
        }
        let response = provider_request_headers_allow_private(
            client,
            "GET",
            &format!("{base}/api/tags"),
            headers,
            None,
        )
        .await?;
        return Ok(response.status().is_success());
    }
    if provider.starts_with("openai-compatible-")
        || provider.starts_with("anthropic-compatible-")
        || provider.starts_with("custom-embedding-")
    {
        use sqlx::Row;
        let row = sqlx::query("SELECT data FROM providerNodes WHERE id=?")
            .bind(provider)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let Some(row) = row else {
            return Err((
                StatusCode::NOT_FOUND,
                if provider.starts_with("custom-embedding-") {
                    "Custom Embedding node not found"
                } else {
                    "OpenAI Compatible node not found"
                }
                .into(),
            ));
        };
        let data: Value = serde_json::from_str(&row.get::<String, _>("data")).unwrap_or_default();
        let base = data["baseUrl"]
            .as_str()
            .unwrap_or_default()
            .trim_end_matches('/');
        if provider.starts_with("anthropic-compatible-") {
            let base = base.strip_suffix("/messages").unwrap_or(base);
            let model = data["defaultModel"]
                .as_str()
                .unwrap_or("claude-3-haiku-20240307");
            let response=provider_request(client,"POST",&format!("{base}/v1/messages"),api_key,"bearer",None,Some(json!({"model":model,"max_tokens":1,"messages":[{"role":"user","content":"test"}]}))).await?;
            return Ok(!matches!(response.status().as_u16(), 401 | 403));
        }
        let models = provider_request(
            client,
            "GET",
            &format!("{base}/models"),
            api_key,
            "bearer",
            None,
            None,
        )
        .await?;
        if provider.starts_with("openai-compatible-") {
            return Ok(models.status().is_success());
        }
        if models.status().is_success() {
            return Ok(true);
        }
        if matches!(models.status().as_u16(), 401 | 403) {
            return Ok(false);
        }
        let response = provider_request(
            client,
            "POST",
            &format!("{base}/embeddings"),
            api_key,
            "bearer",
            None,
            Some(json!({"model":"test","input":"ping"})),
        )
        .await?;
        return Ok(!matches!(response.status().as_u16(), 401 | 403));
    }
    if provider == "cloudflare-ai" {
        let account = specific["accountId"].as_str().unwrap_or_default();
        if account.is_empty() {
            return Ok(false);
        }
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{account}/ai/v1/chat/completions"
        );
        let body = json!({"model":default_model,"messages":[{"role":"user","content":"test"}],"max_tokens":1});
        let response =
            provider_request(client, "POST", &url, api_key, "bearer", None, Some(body)).await?;
        return Ok(!matches!(response.status().as_u16(), 401 | 403 | 404));
    }
    if provider == "nous" {
        let response = provider_request(client,"POST","https://inference-api.nousresearch.com/v1/chat/completions",api_key,"bearer",None,Some(json!({"model":"poolside/laguna-xs-2.1:free","messages":[{"role":"user","content":"ping"}],"max_tokens":1,"stream":false}))).await?;
        return Ok(response.status().is_success());
    }
    if provider == "vertex" || provider == "vertex-partner" {
        if let Ok(credentials) = serde_json::from_str::<Value>(api_key) {
            if credentials["type"] == "service_account" {
                return Ok(credentials["client_email"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty())
                    && credentials["private_key"]
                        .as_str()
                        .is_some_and(|v| !v.is_empty())
                    && credentials["project_id"]
                        .as_str()
                        .is_some_and(|v| !v.is_empty()));
            }
        }
        let mut url=reqwest::Url::parse("https://aiplatform.googleapis.com/v1/publishers/google/models/__probe__:generateContent").unwrap();
        url.query_pairs_mut().append_pair("key", api_key);
        let response = provider_request_headers(
            client,
            "POST",
            url.as_str(),
            HeaderMap::new(),
            Some(json!({})),
        )
        .await?;
        return Ok(!matches!(response.status().as_u16(), 401 | 403));
    }
    if provider == "azure" {
        let endpoint = specific["azureEndpoint"]
            .as_str()
            .unwrap_or_default()
            .trim_end_matches('/');
        if endpoint.is_empty() {
            return Ok(false);
        }
        let deployment = specific["deployment"].as_str().unwrap_or("gpt-4");
        let version = specific["apiVersion"]
            .as_str()
            .unwrap_or("2024-10-01-preview");
        let url = format!(
            "{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={version}"
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "api-key",
            HeaderValue::from_str(api_key)
                .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid API key header".into()))?,
        );
        if let Some(org) = specific["organization"].as_str() {
            if let Ok(value) = HeaderValue::from_str(org) {
                headers.insert("OpenAI-Organization", value);
            }
        }
        let response = provider_request_headers(
            client,
            "POST",
            &url,
            headers,
            Some(json!({"messages":[{"role":"user","content":"test"}],"max_tokens":1})),
        )
        .await?;
        return Ok(!matches!(response.status().as_u16(), 401 | 403));
    }
    let kinds = meta["serviceKinds"].as_array().cloned().unwrap_or_default();
    let is_web_only = !kinds.is_empty()
        && kinds
            .iter()
            .all(|v| matches!(v.as_str(), Some("webSearch" | "webFetch")));
    if is_web_only {
        if meta["webProbe"].is_null() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Provider validation not supported".into(),
            ));
        }
        let cfg = &meta["webProbe"];
        if cfg["authType"] == "none" {
            return Ok(true);
        }
        let mut url =
            reqwest::Url::parse(cfg["baseUrl"].as_str().unwrap_or_default()).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "Provider validation URL is invalid".into(),
                )
            })?;
        match cfg["authHeader"].as_str().unwrap_or("bearer") {
            "key" => {
                url.query_pairs_mut()
                    .append_pair("key", api_key)
                    .append_pair("q", "ping")
                    .append_pair("cx", "test");
            }
            "api_key" => {
                url.query_pairs_mut()
                    .append_pair("api_key", api_key)
                    .append_pair("q", "ping")
                    .append_pair("engine", "google");
            }
            _ => {}
        }
        let mut headers = json_headers(&cfg["extraHeaders"]);
        match cfg["authHeader"].as_str().unwrap_or("bearer") {
            "bearer" => insert_header(&mut headers, "Authorization", &format!("Bearer {api_key}"))?,
            "x-api-key" => insert_header(&mut headers, "x-api-key", api_key)?,
            "x-subscription-token" => insert_header(&mut headers, "x-subscription-token", api_key)?,
            _ => {}
        }
        let body = (cfg["method"] == "POST")
            .then(|| json!({"query":"ping","q":"ping","url":"https://example.com"}));
        let response = provider_request_headers(
            client,
            cfg["method"].as_str().unwrap_or("GET"),
            url.as_str(),
            headers,
            body,
        )
        .await?;
        return Ok(!matches!(response.status().as_u16(), 401 | 403));
    }
    let media_kinds = [
        "tts",
        "embedding",
        "stt",
        "image",
        "video",
        "music",
        "imageToText",
    ];
    let is_media_only = !kinds.is_empty()
        && kinds
            .iter()
            .all(|v| v.as_str().is_some_and(|kind| media_kinds.contains(&kind)));
    if is_media_only {
        if meta["mediaProbe"].is_null()
            || meta["mediaProbe"]["authType"] == "none"
            || matches!(
                meta["mediaProbe"]["authHeader"].as_str(),
                Some("playht" | "aws-sigv4")
            )
        {
            return Ok(true);
        }
        let cfg = &meta["mediaProbe"];
        let mut headers = json_headers(&cfg["extraHeaders"]);
        match cfg["authHeader"].as_str().unwrap_or("bearer") {
            "bearer" => insert_header(&mut headers, "Authorization", &format!("Bearer {api_key}"))?,
            "key" => insert_header(&mut headers, "Authorization", &format!("Key {api_key}"))?,
            "x-api-key" => insert_header(&mut headers, "x-api-key", api_key)?,
            "x-key" => insert_header(&mut headers, "x-key", api_key)?,
            "xi-api-key" => insert_header(&mut headers, "xi-api-key", api_key)?,
            "token" => insert_header(&mut headers, "Authorization", &format!("Token {api_key}"))?,
            "basic" => insert_header(&mut headers, "Authorization", &format!("Basic {api_key}"))?,
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Provider validation not supported".into(),
                ));
            }
        }
        let method = cfg["method"].as_str().unwrap_or("POST");
        let body = (method != "GET")
            .then(|| json!({"input":"ping","text":"ping","prompt":"ping","model":default_model}));
        let response = provider_request_headers(
            client,
            method,
            cfg["baseUrl"].as_str().unwrap_or_default(),
            headers,
            body,
        )
        .await?;
        return Ok(!matches!(response.status().as_u16(), 401 | 403));
    }
    if provider == "gemini" {
        let mut url =
            reqwest::Url::parse("https://generativelanguage.googleapis.com/v1/models").unwrap();
        url.query_pairs_mut().append_pair("key", api_key);
        let response = provider_request(client, "GET", url.as_str(), "", "", None, None).await?;
        return Ok(response.status().is_success());
    }
    if meta["credentialForm"] == "aws" {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "AWS Bedrock credential validation is not implemented in Rust yet".into(),
        ));
    }
    if probe["noAuth"] == true {
        return Ok(true);
    }
    let base = probe["baseUrl"].as_str().unwrap_or_default();
    let format = probe["format"].as_str().unwrap_or_default();
    let auth_header = probe["authHeader"].as_str().unwrap_or("Authorization");
    if base.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Provider validation not supported".into(),
        ));
    }
    if format == "claude" {
        let mut headers = json_headers(&probe["headers"]);
        if provider == "anthropic" || auth_header.eq_ignore_ascii_case("x-api-key") {
            insert_header(&mut headers, "x-api-key", api_key)?
        } else {
            let value = if probe["authScheme"] == "raw" {
                api_key.to_string()
            } else {
                format!("Bearer {api_key}")
            };
            insert_header(&mut headers, auth_header, &value)?
        }
        insert_header(&mut headers, "anthropic-version", "2023-06-01")?;
        let body = json!({"model":if default_model.is_empty(){"claude-sonnet-4-20250514"}else{&default_model},"max_tokens":1,"messages":[{"role":"user","content":"test"}]});
        let response = provider_request_headers(client, "POST", base, headers, Some(body)).await?;
        return Ok(!matches!(response.status().as_u16(), 401 | 403));
    }
    if format == "gemini" {
        return Ok(false);
    }
    let mut headers = json_headers(&probe["headers"]);
    if auth_header.eq_ignore_ascii_case("x-api-key") {
        insert_header(&mut headers, auth_header, api_key)?
    } else {
        let value = if probe["authScheme"] == "raw" {
            api_key.to_string()
        } else {
            format!("Bearer {api_key}")
        };
        insert_header(&mut headers, auth_header, &value)?
    }
    let models_url = probe["validateUrl"]
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            base.replace("/chat/completions", "/models")
                .replace("/chatbot", "/models")
        });
    let model_response =
        provider_request_headers(client, "GET", &models_url, headers.clone(), None).await;
    match model_response {
        Ok(response) if provider == "xai" => {
            return Ok(response.status().as_u16() == 200 || response.status().as_u16() == 403);
        }
        Ok(response) if provider == "xiaomi-tokenplan" => {
            return Ok(response.status().as_u16() != 401);
        }
        Ok(response) if matches!(response.status().as_u16(), 401 | 403) => return Ok(false),
        Ok(response) if response.status().is_success() => return Ok(true),
        _ => {}
    }
    if default_model.is_empty() {
        return Ok(false);
    }
    let response=provider_request_headers(client,"POST",base,headers,Some(json!({"model":default_model,"messages":[{"role":"user","content":"ping"}],"max_tokens":1}))).await?;
    Ok(!matches!(response.status().as_u16(), 401 | 403))
}

fn provider_default_model(provider: &str) -> String {
    let catalog: Vec<Value> =
        serde_json::from_str(include_str!("model_catalog.json")).unwrap_or_default();
    catalog
        .iter()
        .find(|m| m["provider"] == provider && m["kind"] == "llm")
        .or_else(|| catalog.iter().find(|m| m["provider"] == provider))
        .and_then(|m| m["model"].as_str())
        .unwrap_or("test")
        .to_string()
}

fn json_headers(value: &Value) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(object) = value.as_object() {
        for (name, value) in object {
            if let Some(value) = value.as_str() {
                if let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    headers.insert(name, value);
                }
            }
        }
    }
    headers
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
) -> Result<(), (StatusCode, String)> {
    let name = axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid provider auth header".into(),
        )
    })?;
    let value = HeaderValue::from_str(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid provider credential".into(),
        )
    })?;
    headers.insert(name, value);
    Ok(())
}

async fn provider_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    api_key: &str,
    scheme: &str,
    header_name: Option<&str>,
    body: Option<Value>,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let mut headers = HeaderMap::new();
    if !api_key.is_empty() {
        let value = if scheme == "raw" {
            api_key.to_string()
        } else {
            format!("Bearer {api_key}")
        };
        insert_header(&mut headers, header_name.unwrap_or("Authorization"), &value)?;
    }
    provider_request_headers(client, method, url, headers, body).await
}

async fn provider_request_headers(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: HeaderMap,
    body: Option<Value>,
) -> Result<reqwest::Response, (StatusCode, String)> {
    provider_request_headers_inner(client, method, url, headers, body, false).await
}

async fn provider_request_headers_allow_private(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: HeaderMap,
    body: Option<Value>,
) -> Result<reqwest::Response, (StatusCode, String)> {
    provider_request_headers_inner(client, method, url, headers, body, true).await
}

async fn provider_request_headers_inner(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: HeaderMap,
    body: Option<Value>,
    allow_private: bool,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let parsed = reqwest::Url::parse(url).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Provider validation URL is invalid".into(),
        )
    })?;
    if !provider_url_is_public(&parsed).await
        && !(allow_private && provider_url_is_private(&parsed).await)
    {
        return Err((StatusCode::BAD_REQUEST, "URL not allowed".into()));
    }
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid provider validation method".into(),
        )
    })?;
    let mut request = client.request(method, parsed).headers(headers);
    if let Some(body) = body {
        request = request.json(&body);
    }
    request
        .send()
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

async fn provider_url_is_private(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if ["localhost", "ip6-localhost", "ip6-loopback"].contains(&host.as_str())
        || [".internal", ".local", ".localhost"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return !public_ip(ip);
    }
    let port = url.port_or_known_default().unwrap_or(80);
    match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addresses) => {
            let mut any = false;
            for address in addresses {
                any = true;
                if public_ip(address.ip()) {
                    return false;
                }
            }
            any
        }
        Err(_) => false,
    }
}

fn provider_models_error(status: u16) -> String {
    match status {
        401 | 403 => "API key unauthorized".into(),
        404 => "/models endpoint not found - try chat validation with model ID".into(),
        500..=599 => "Server error - try again later".into(),
        _ => format!("Unexpected response ({status})"),
    }
}

fn provider_chat_error(status: u16) -> String {
    match status {
        401 | 403 => "API key unauthorized".into(),
        400 => "Invalid model or bad request".into(),
        404 => "Chat endpoint not found".into(),
        500..=599 => "Server error - try again later".into(),
        _ => format!("Chat request failed ({status})"),
    }
}

fn provider_validation_error(error: reqwest::Error) -> Response {
    let message = if error.is_timeout() {
        "Request timeout (>10s) - provider node not responding".to_string()
    } else if let Some(source) = std::error::Error::source(&error) {
        let source = source.to_string().to_ascii_lowercase();
        if source.contains("connection refused") {
            "Connection refused - provider node offline or unreachable".into()
        } else if source.contains("dns") || source.contains("name or service not known") {
            "DNS lookup failed - invalid domain or network issue".into()
        } else if source.contains("certificate") || source.contains("cert") {
            "SSL certificate verification failed".into()
        } else {
            format!("Network connection failed - check URL and network connectivity: {source}")
        }
    } else {
        format!("Network connection failed - check URL and network connectivity: {error}")
    };
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"valid":false,"error":message})),
    )
        .into_response()
}

async fn provider_url_is_public(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost"
        || host == "ip6-localhost"
        || host == "ip6-loopback"
        || [".internal", ".local", ".localhost"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return public_ip(ip);
    }
    let port = url.port_or_known_default().unwrap_or(80);
    match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addresses) => {
            let mut any = false;
            for address in addresses {
                any = true;
                if !public_ip(address.ip()) {
                    return false;
                }
            }
            any
        }
        Err(_) => false,
    }
}

fn public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && (b == 18 || b == 19 || b == 51 && c == 100))
                || (a == 203 && b == 0 && c == 113))
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_ip(mapped.into());
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

async fn api_test_provider_batch(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Response {
    use sqlx::Row;
    let Some(mode) = input.get("mode").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"mode is required"})),
        )
            .into_response();
    };
    let provider_id = input.get("providerId").and_then(Value::as_str);
    if mode == "provider" && provider_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"providerId is required"})),
        )
            .into_response();
    }
    if !["provider", "oauth", "free", "apikey", "compatible", "all"].contains(&mode) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":"Invalid mode. Use: provider, oauth, free, apikey, compatible, all"}))).into_response();
    }
    let rows = match sqlx::query("SELECT id,provider,authType,name,email FROM providerConnections WHERE isActive=1 ORDER BY COALESCE(priority,999),updatedAt")
        .fetch_all(&state.db).await {
        Ok(rows) => rows,
        Err(error) => return ApiError::upstream(error.to_string()).into_response(),
    };
    let metadata: Value =
        serde_json::from_str(include_str!("provider_metadata.json")).unwrap_or_default();
    let selected: Vec<(String, String, String, String, String)> = rows
        .into_iter()
        .filter_map(|row| {
            let id = row.try_get::<String, _>("id").ok()?;
            let provider = row.try_get::<String, _>("provider").ok()?;
            let auth_type = row
                .try_get::<String, _>("authType")
                .unwrap_or_else(|_| "apikey".into());
            let name = row
                .try_get::<Option<String>, _>("name")
                .ok()
                .flatten()
                .unwrap_or_default();
            let email = row
                .try_get::<Option<String>, _>("email")
                .ok()
                .flatten()
                .unwrap_or_default();
            let compatible = provider.starts_with("openai-compatible-")
                || provider.starts_with("anthropic-compatible-");
            let category = metadata[&provider]["category"].as_str().unwrap_or_default();
            let group = if auth_type == "oauth" && category == "free" {
                "free"
            } else {
                auth_type.as_str()
            };
            let matches = match mode {
                "provider" => provider_id == Some(provider.as_str()),
                "oauth" => group == "oauth",
                "free" => group == "free",
                "apikey" => group == "apikey",
                "compatible" => compatible,
                _ => true,
            };
            matches.then_some((id, provider, auth_type, name, email))
        })
        .collect();
    let mut results = Vec::with_capacity(selected.len());
    for (id, provider, auth_type, name, email) in selected {
        let started = Instant::now();
        let response = api_test_provider_connection(State(state.clone()), Path(id.clone())).await;
        let status = response.status();
        let result = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .ok()
            .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
            .unwrap_or_else(|| json!({"valid":false,"error":"Failed to read test result"}));
        let connection_name = if !name.is_empty() {
            name
        } else if !email.is_empty() {
            email
        } else {
            provider.clone()
        };
        results.push(json!({
            "provider":provider,
            "connectionId":id,
            "connectionName":connection_name,
            "authType":auth_type,
            "valid":result["valid"]==true,
            "latencyMs":started.elapsed().as_millis(),
            "error":result["error"],
            "diagnosis":null,
            "statusCode":result.get("statusCode").cloned().or_else(||(!status.is_success()).then(||json!(status.as_u16()))),
            "testedAt":timestamp(),
        }));
    }
    let passed = results.iter().filter(|r| r["valid"] == true).count();
    Json(json!({
        "mode":mode,
        "providerId":provider_id,
        "results":results,
        "testedAt":timestamp(),
        "summary":{"total":results.len(),"passed":passed,"failed":results.len()-passed},
    }))
    .into_response()
}

async fn api_clear_model_cooldown(
    State(state): State<AppState>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if input["action"] != "clearCooldown"
        || input["provider"].as_str().is_none_or(str::is_empty)
        || input["model"].as_str().is_none_or(str::is_empty)
    {
        return Err(ApiError::bad_request("Invalid request"));
    }
    use sqlx::Row;
    let provider = input["provider"].as_str().unwrap_or_default();
    let model = input["model"].as_str().unwrap_or_default();
    let lock_key = format!("modelLock_{model}");
    let rows = sqlx::query("SELECT id,data FROM providerConnections WHERE provider=?")
        .bind(provider)
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        let id: String = row.try_get("id")?;
        let raw: String = row.try_get("data")?;
        let mut data = serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| json!({}));
        let Some(object) = data.as_object_mut() else {
            continue;
        };
        if !object.contains_key(&lock_key) {
            continue;
        }
        object.insert(lock_key.clone(), Value::Null);
        if data["testStatus"] == "unavailable" {
            data["testStatus"] = json!("active");
            data["lastError"] = Value::Null;
            data["lastErrorAt"] = Value::Null;
            data["backoffLevel"] = json!(0);
        }
        sqlx::query("UPDATE providerConnections SET data=?,updatedAt=? WHERE id=?")
            .bind(data.to_string())
            .bind(timestamp())
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    Ok(Json(json!({"ok":true})))
}

async fn set_dashboard_model_alias(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let model = b
        .get("model")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Model and alias required"))?;
    let alias = b
        .get("alias")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::bad_request("Model and alias required"))?;
    let aliases = kv_map(&s.db, "modelAliases").await?;
    if aliases
        .iter()
        .any(|(key, value)| key != model && value.as_str() == Some(alias))
    {
        return Err(ApiError::bad_request("Alias already in use"));
    }
    kv_set(&s.db, "modelAliases", model, &json!(alias)).await?;
    Ok(Json(json!({"success":true,"model":model,"alias":alias})))
}

async fn save_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ProviderInput>,
) -> Result<Json<Value>, ApiError> {
    authorize(&state, &headers).await?;
    validate_provider(&input)?;
    let provider = store::save_provider(&state.db, input).await?;
    Ok(Json(json!({"provider":provider_json(provider)})))
}

async fn remove_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&state, &headers).await?;
    if store::delete_provider(&state.db, &id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("Provider not found"))
    }
}

async fn list_combos(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize(&state, &headers).await?;
    let combos: Vec<Value> = store::list_combos(&state.db)
        .await?
        .into_iter()
        .map(combo_json)
        .collect();
    Ok(Json(json!({"combos":combos})))
}

async fn save_combo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ComboInput>,
) -> Result<Json<Value>, ApiError> {
    authorize(&state, &headers).await?;
    if input.id.as_deref().is_some_and(|id| !safe_id(id)) {
        return Err(ApiError::bad_request(
            "Combo id may contain only letters, numbers, '.', '_' and '-'",
        ));
    }
    if input.name.trim().is_empty() || input.models.is_empty() {
        return Err(ApiError::bad_request(
            "Combo name and at least one provider/model target are required",
        ));
    }
    for target in &input.models {
        let Some((provider, model)) = target.split_once('/') else {
            return Err(ApiError::bad_request(
                "Combo targets must use provider/model format",
            ));
        };
        if provider.is_empty() || model.is_empty() {
            return Err(ApiError::bad_request(
                "Combo targets must use provider/model format",
            ));
        }
    }
    let combo = store::save_combo(&state.db, input).await?;
    Ok(Json(json!({"combo":combo_json(combo)})))
}

async fn remove_combo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&state, &headers).await?;
    if store::delete_combo(&state.db, &id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("Combo not found"))
    }
}

async fn list_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize(&state, &headers).await?;
    Ok(Json(
        json!({"requests":store::recent_requests(&state.db, 50).await?}),
    ))
}

async fn api_usage_logs(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let rows=sqlx::query("SELECT created_at,requested_model,routed_model,status FROM request_log ORDER BY id DESC LIMIT 200").fetch_all(&s.db).await?;
    let logs = rows
        .into_iter()
        .map(|r| {
            let time = r.get::<String, _>("created_at");
            let model = r.get::<String, _>("requested_model");
            let provider = r
                .get::<String, _>("routed_model")
                .split('/')
                .next()
                .unwrap_or("-")
                .to_uppercase();
            let status = r.get::<i64, _>("status");
            json!(format!(
                "{time} | {model} | {provider} | - | - | - | {status}"
            ))
        })
        .collect::<Vec<_>>();
    Ok(Json(json!(logs)))
}

async fn api_usage_stats(
    State(s): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let period = uri
        .query()
        .and_then(|q| query_value(q, "period"))
        .unwrap_or("7d");
    if !["today", "24h", "7d", "30d", "60d", "all"].contains(&period) {
        return Err(ApiError::bad_request("Invalid period"));
    }
    let rows = if period == "all" {
        sqlx::query("SELECT timestamp,provider,model,connectionId,apiKey,endpoint,promptTokens,completionTokens,cost,status,tokens FROM usageHistory ORDER BY id DESC")
            .fetch_all(&s.db).await?
    } else {
        let now = chrono::Utc::now();
        let since = match period {
            "today" => now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc(),
            "24h" => now - chrono::Duration::hours(24),
            "30d" => now - chrono::Duration::days(30),
            "60d" => now - chrono::Duration::days(60),
            _ => now - chrono::Duration::days(7),
        };
        sqlx::query("SELECT timestamp,provider,model,connectionId,apiKey,endpoint,promptTokens,completionTokens,cost,status,tokens FROM usageHistory WHERE timestamp >= ? ORDER BY id DESC")
            .bind(since.to_rfc3339()).fetch_all(&s.db).await?
    };
    let mut total_requests = 0_i64;
    let (mut prompt, mut completion, mut cached, mut cost) = (0_i64, 0_i64, 0_i64, 0_f64);
    let mut by_provider = serde_json::Map::new();
    let mut by_model = serde_json::Map::new();
    let mut by_account = serde_json::Map::new();
    let mut by_endpoint = serde_json::Map::new();
    let mut by_api_key = serde_json::Map::new();
    let mut recent = Vec::new();
    for row in rows.iter().rev() {
        let p: i64 = row.try_get("promptTokens").unwrap_or(0);
        let c: i64 = row.try_get("completionTokens").unwrap_or(0);
        let co: f64 = row.try_get("cost").unwrap_or(0.0);
        let tokens: Value = row
            .try_get::<Option<String>, _>("tokens")
            .unwrap_or_default()
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_else(|| json!({}));
        let p = tokens
            .get("prompt_tokens")
            .or_else(|| tokens.get("input_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(p);
        let c = tokens
            .get("completion_tokens")
            .or_else(|| tokens.get("output_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(c);
        let ca = tokens
            .get("cached_tokens")
            .or_else(|| tokens.get("cache_read_input_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let provider: String = row
            .try_get::<Option<String>, _>("provider")
            .unwrap_or_default()
            .unwrap_or_default();
        let model: String = row
            .try_get::<Option<String>, _>("model")
            .unwrap_or_default()
            .unwrap_or_default();
        let account: String = row
            .try_get::<Option<String>, _>("connectionId")
            .unwrap_or_default()
            .unwrap_or_default();
        let endpoint: String = row
            .try_get::<Option<String>, _>("endpoint")
            .unwrap_or_default()
            .unwrap_or_else(|| "Unknown".into());
        let api_key: String = row
            .try_get::<Option<String>, _>("apiKey")
            .unwrap_or_default()
            .unwrap_or_else(|| "local-no-key".into());
        let timestamp: String = row.try_get("timestamp").unwrap_or_default();
        let status: String = row
            .try_get::<Option<String>, _>("status")
            .unwrap_or_default()
            .unwrap_or_else(|| "ok".into());
        total_requests += 1;
        prompt += p;
        completion += c;
        cached += ca;
        cost += co;
        update_usage_counter(&mut by_provider, &provider, p, c, ca, co, None);
        update_usage_counter(
            &mut by_model,
            &format!("{model} ({provider})"),
            p,
            c,
            ca,
            co,
            Some(json!({"rawModel":model,"provider":provider,"lastUsed":timestamp})),
        );
        if !account.is_empty() {
            update_usage_counter(
                &mut by_account,
                &format!("{model} ({provider} - {account})"),
                p,
                c,
                ca,
                co,
                Some(
                    json!({"rawModel":model,"provider":provider,"connectionId":account,"accountName":account,"lastUsed":timestamp}),
                ),
            );
        }
        update_usage_counter(
            &mut by_endpoint,
            &format!("{endpoint}|{model}|{provider}"),
            p,
            c,
            ca,
            co,
            Some(
                json!({"endpoint":endpoint,"rawModel":model,"provider":provider,"lastUsed":timestamp}),
            ),
        );
        update_usage_counter(
            &mut by_api_key,
            &format!("{api_key}|{model}|{provider}"),
            p,
            c,
            ca,
            co,
            Some(
                json!({"rawModel":model,"provider":provider,"apiKeyMasked":mask_usage_key(&api_key),"keyName":if api_key=="local-no-key" {"Local (No API Key)"} else {"API Key"},"lastUsed":timestamp}),
            ),
        );
        if recent.len() < 20 && (p != 0 || c != 0) {
            recent.push(json!({"timestamp":timestamp,"model":model,"provider":provider,"promptTokens":p,"completionTokens":c,"cachedTokens":ca,"status":status}));
        }
    }
    Ok(Json(
        json!({"totalRequests":total_requests,"totalPromptTokens":prompt,"totalCompletionTokens":completion,"totalCachedTokens":cached,"totalCost":cost,"byProvider":by_provider,"byModel":by_model,"byAccount":by_account,"byApiKey":by_api_key,"byEndpoint":by_endpoint,"last10Minutes":[],"pending":{"byModel":{},"byAccount":{}},"activeRequests":[],"recentRequests":recent,"errorProvider":""}),
    ))
}

fn update_usage_counter(
    map: &mut serde_json::Map<String, Value>,
    key: &str,
    prompt: i64,
    completion: i64,
    cached: i64,
    cost: f64,
    meta: Option<Value>,
) {
    let entry = map.entry(key.to_string()).or_insert_with(
        || json!({"requests":0,"promptTokens":0,"completionTokens":0,"cachedTokens":0,"cost":0.0}),
    );
    entry["requests"] = json!(entry["requests"].as_i64().unwrap_or(0) + 1);
    entry["promptTokens"] = json!(entry["promptTokens"].as_i64().unwrap_or(0) + prompt);
    entry["completionTokens"] = json!(entry["completionTokens"].as_i64().unwrap_or(0) + completion);
    entry["cachedTokens"] = json!(entry["cachedTokens"].as_i64().unwrap_or(0) + cached);
    entry["cost"] = json!(entry["cost"].as_f64().unwrap_or(0.0) + cost);
    if let Some(meta) = meta {
        if let (Some(dst), Some(src)) = (entry.as_object_mut(), meta.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
    }
}

fn mask_usage_key(key: &str) -> Value {
    if key == "local-no-key" {
        return Value::Null;
    }
    let masked = if key.len() <= 12 {
        format!("{}***", key.chars().next().unwrap_or('*'))
    } else {
        format!("{}***{}", &key[..8], &key[key.len() - 4..])
    };
    json!(masked)
}

async fn api_usage_providers(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT DISTINCT provider FROM usageHistory WHERE provider IS NOT NULL AND provider != '' ORDER BY provider").fetch_all(&s.db).await?;
    Ok(Json(
        json!({"providers": rows.into_iter().map(|id| json!({"id":id,"name":id})).collect::<Vec<_>>()}),
    ))
}

async fn api_connection_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(connection_id): Path<String>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    if let Err(error) = authorize(&state, &headers).await {
        return error.into_response();
    }
    let row = match sqlx::query(
        "SELECT provider,authType,data,isActive FROM providerConnections WHERE id=?",
    )
    .bind(&connection_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::not_found("Connection not found").into_response(),
        Err(error) => return ApiError::from(error).into_response(),
    };
    use sqlx::Row;
    let provider: String = row.try_get("provider").unwrap_or_default();
    let auth_type: String = row.try_get("authType").unwrap_or_default();
    let raw: String = row.try_get("data").unwrap_or_default();
    let data: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
    let settings = match sqlx::query_scalar::<_, String>("SELECT data FROM settings WHERE id=1")
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(raw)) => serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| json!({})),
        Ok(None) => json!({}),
        Err(error) => return ApiError::from(error).into_response(),
    };

    // The Rust dashboard currently owns Claude and Codex quota reads. Keep the
    // established Node handlers as the compatibility path for other providers,
    // custom proxy routes, and provider-specific auth retry behavior.
    if !matches!(provider.as_str(), "claude" | "codex")
        || (provider == "claude" && auth_type != "oauth")
        || (provider == "codex" && !matches!(auth_type.as_str(), "oauth" | "access_token"))
        || data["providerSpecificData"]["connectionProxyEnabled"] == true
        || data["providerSpecificData"]["strictProxy"] == true
        || data["providerSpecificData"]["connectionProxyUrl"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        || data["providerSpecificData"]["vercelRelayUrl"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        || settings["outboundProxyEnabled"] == true
    {
        return node_usage_fallback();
    }

    let mut account = match store::list_routing_accounts(&state.db).await {
        Ok(accounts) => match accounts
            .into_iter()
            .find(|account| account.connection_id.as_deref() == Some(&connection_id))
        {
            Some(account) => account,
            None => return node_usage_fallback(),
        },
        Err(error) => return ApiError::from(error).into_response(),
    };
    if account.auth_type == "oauth" {
        if let Err(error) = refresh_oauth_account(&state, &mut account).await {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": format!("Credential refresh failed: {error}")})),
            )
                .into_response();
        }
    }
    let Some(access_token) = (!account.api_key.is_empty()).then_some(account.api_key.as_str())
    else {
        return node_usage_fallback();
    };

    let force = uri
        .query()
        .is_some_and(|query| query.split('&').any(|pair| pair == "force=1"));
    let cache_key = usage_cache_key(&provider, access_token);
    let cache = USAGE_CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    if !force && provider == "claude" {
        if let Some(value) = cache
            .lock()
            .await
            .get(&cache_key)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.value.clone())
        {
            return Json(value).into_response();
        }
    }

    let result = if provider == "claude" {
        fetch_claude_usage(&state, access_token).await
    } else {
        fetch_codex_usage(&state, access_token).await
    };
    match result {
        Ok(Some(usage)) => {
            if provider == "claude" {
                let mut cache = cache.lock().await;
                cache.retain(|_, entry| entry.expires_at > Instant::now());
                cache.insert(
                    cache_key,
                    UsageCacheEntry {
                        value: usage.clone(),
                        expires_at: Instant::now() + Duration::from_secs(300),
                    },
                );
            }
            Json(usage).into_response()
        }
        Ok(None) => node_usage_fallback(),
        Err(error) => {
            tracing::warn!(provider, %error, "Rust usage request failed; falling back to Node");
            node_usage_fallback()
        }
    }
}

async fn api_codex_reset_credits(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(connection_id): Path<String>,
) -> Response {
    if let Err(error) = authorize(&state, &headers).await {
        return error.into_response();
    }
    let row = match sqlx::query(
        "SELECT provider,authType,data FROM providerConnections WHERE id=? AND isActive=1",
    )
    .bind(&connection_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::not_found("Connection not found").into_response(),
        Err(error) => return ApiError::from(error).into_response(),
    };
    use sqlx::Row;
    let provider: String = row.try_get("provider").unwrap_or_default();
    let auth_type: String = row.try_get("authType").unwrap_or_default();
    let raw: String = row.try_get("data").unwrap_or_default();
    let data: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
    if provider != "codex" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Codex reset credits are only available for Codex connections."})),
        )
            .into_response();
    }
    if !matches!(auth_type.as_str(), "oauth" | "access_token") {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error":"Codex reset credits require an OAuth or access-token connection."}),
            ),
        )
            .into_response();
    }
    let specific = &data["providerSpecificData"];
    if specific["connectionProxyEnabled"] == true
        || specific["strictProxy"] == true
        || specific["connectionProxyUrl"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        || specific["vercelRelayUrl"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    {
        return node_usage_fallback();
    }
    let mut account = match store::list_routing_accounts(&state.db).await {
        Ok(accounts) => match accounts
            .into_iter()
            .find(|account| account.connection_id.as_deref() == Some(connection_id.as_str()))
        {
            Some(account) => account,
            None => return node_usage_fallback(),
        },
        Err(error) => return ApiError::from(error).into_response(),
    };
    if account.auth_type == "oauth" {
        if let Err(error) = refresh_oauth_account(&state, &mut account).await {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":format!("Credential refresh failed: {error}")})),
            )
                .into_response();
        }
    }
    if account.api_key.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"No Codex access token available. Please re-authorize the connection."}))).into_response();
    }
    let mut request = state
        .http
        .get("https://chatgpt.com/backend-api/wham/rate-limit-reset-credits")
        .bearer_auth(&account.api_key)
        .header(header::ACCEPT, "application/json")
        .header("openai-beta", "codex-1")
        .header("originator", "codex_cli_rs");
    let account_id = ["workspaceId", "accountId", "chatgptAccountId"]
        .iter()
        .find_map(|key| specific[*key].as_str().filter(|value| !value.is_empty()));
    if let Some(account_id) = account_id {
        request = request.header("chatgpt-account-id", account_id);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    let status = response.status();
    let payload = response.json::<Value>().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let message = payload
            .get("message")
            .or_else(|| payload.get("error"))
            .or_else(|| payload.get("detail"))
            .and_then(|value| {
                value
                    .as_str()
                    .or_else(|| value.get("message").and_then(Value::as_str))
            })
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!("Codex reset credits API unavailable ({}).", status.as_u16())
            });
        return (StatusCode::BAD_GATEWAY, Json(json!({"error":message}))).into_response();
    }
    let credits = payload["credits"].as_array().into_iter().flatten().map(|credit| {
        json!({
            "status":credit["status"].as_str().unwrap_or("unknown"),
            "grantedAt":parse_reset_time(credit.get("granted_at").or_else(|| credit.get("grantedAt")).unwrap_or(&Value::Null)),
            "expiresAt":parse_reset_time(credit.get("expires_at").or_else(|| credit.get("expiresAt")).unwrap_or(&Value::Null))
        })
    }).collect::<Vec<_>>();
    let available = payload
        .get("available_count")
        .or_else(|| payload.get("availableCount"))
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0.0)
        .max(0.0);
    Json(json!({"availableCount":available,"credits":credits})).into_response()
}

async fn api_consume_codex_reset_credit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(connection_id): Path<String>,
) -> Response {
    if let Err(error) = authorize(&state, &headers).await {
        return error.into_response();
    }
    let row = match sqlx::query(
        "SELECT provider,authType,data FROM providerConnections WHERE id=? AND isActive=1",
    )
    .bind(&connection_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::not_found("Connection not found").into_response(),
        Err(error) => return ApiError::from(error).into_response(),
    };
    use sqlx::Row;
    let provider: String = row.try_get("provider").unwrap_or_default();
    let auth_type: String = row.try_get("authType").unwrap_or_default();
    let raw: String = row.try_get("data").unwrap_or_default();
    let data: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
    if provider != "codex" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Codex reset credits are only available for Codex connections."})),
        )
            .into_response();
    }
    if !matches!(auth_type.as_str(), "oauth" | "access_token") {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error":"Codex reset credits require an OAuth or access-token connection."}),
            ),
        )
            .into_response();
    }
    let specific = &data["providerSpecificData"];
    if specific["connectionProxyEnabled"] == true
        || specific["strictProxy"] == true
        || specific["connectionProxyUrl"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        || specific["vercelRelayUrl"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    {
        return node_usage_fallback();
    }
    let mut account = match store::list_routing_accounts(&state.db).await {
        Ok(accounts) => match accounts
            .into_iter()
            .find(|account| account.connection_id.as_deref() == Some(connection_id.as_str()))
        {
            Some(account) => account,
            None => return node_usage_fallback(),
        },
        Err(error) => return ApiError::from(error).into_response(),
    };
    if account.auth_type == "oauth" {
        if let Err(error) = refresh_oauth_account(&state, &mut account).await {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":format!("Credential refresh failed: {error}")})),
            )
                .into_response();
        }
    }
    if account.api_key.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"No Codex access token available. Please re-authorize the connection."}))).into_response();
    }

    let redeem_request_id = uuid::Uuid::new_v4().to_string();
    let mut consume_result =
        match send_codex_reset_credit(&state.http, &account.api_key, &redeem_request_id).await {
            Ok(result) => result,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":error})),
                )
                    .into_response();
            }
        };
    let has_refresh_token = data["refreshToken"]
        .as_str()
        .is_some_and(|token| !token.is_empty());
    if account.auth_type == "oauth"
        && codex_reset_result_is_auth_expired(&consume_result)
        && has_refresh_token
    {
        if refresh_oauth_account_with_force(&state, &mut account, true)
            .await
            .is_ok()
        {
            if let Ok(result) =
                send_codex_reset_credit(&state.http, &account.api_key, &redeem_request_id).await
            {
                consume_result = result;
            }
        }
    }
    codex_reset_consume_response(consume_result, &redeem_request_id)
}

async fn send_codex_reset_credit(
    client: &reqwest::Client,
    access_token: &str,
    redeem_request_id: &str,
) -> Result<Value, String> {
    let response = client
        .post("https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume")
        .bearer_auth(access_token)
        .header(header::ACCEPT, "application/json")
        .json(&json!({"redeem_request_id":redeem_request_id}))
        .send()
        .await
        .map_err(|error| format!("Failed to consume Codex reset credit: {error}"))?;
    let status = response.status();
    let data = response.json::<Value>().await.unwrap_or(Value::Null);
    let code = data.get("code").cloned().unwrap_or(Value::Null);
    let windows_reset = data
        .get("windows_reset")
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0.0);
    let ok = status.is_success() && (code.as_str() == Some("reset") || windows_reset > 0.0);
    Ok(json!({
        "ok":ok,
        "noCredit":status.is_success() && code == "no_credit",
        "status":status.as_u16(),
        "code":code,
        "windowsReset":windows_reset,
        "message":data.get("message").cloned().unwrap_or(Value::Null),
        "raw":data
    }))
}

fn codex_reset_result_is_auth_expired(result: &Value) -> bool {
    ["message", "code"]
        .into_iter()
        .filter_map(|key| result.get(key).and_then(Value::as_str))
        .chain(
            ["detail", "error"]
                .into_iter()
                .filter_map(|key| result.pointer(&format!("/raw/{key}")))
                .filter_map(|value| value.as_str().or_else(|| value["message"].as_str())),
        )
        .map(str::to_ascii_lowercase)
        .any(|value| {
            [
                "expired",
                "authentication",
                "unauthorized",
                "401",
                "re-authorize",
            ]
            .iter()
            .any(|pattern| value.contains(pattern))
        })
}

fn codex_reset_consume_response(result: Value, redeem_request_id: &str) -> Response {
    if result["ok"] == true {
        return Json(json!({
            "code":result["code"], "reset":true,
            "windows_reset":result["windowsReset"],
            "redeemRequestId":redeem_request_id,
            "credit":result.pointer("/raw/credit").cloned().unwrap_or(Value::Null)
        }))
        .into_response();
    }
    if result["noCredit"] == true {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "code":"no_credit", "reset":false,
                "windows_reset":result["windowsReset"],
                "message":"No Codex reset credits available."
            })),
        )
            .into_response();
    }
    let status = result["status"].as_u64().unwrap_or_default();
    let response_status = if (400..500).contains(&status) {
        StatusCode::from_u16(status as u16).unwrap_or(StatusCode::BAD_GATEWAY)
    } else {
        StatusCode::BAD_GATEWAY
    };
    let message = result["message"]
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or("Codex reset credit consume returned an unexpected response.");
    (
        response_status,
        Json(json!({
            "code":result["code"].as_str().unwrap_or("unknown_response"),
            "reset":false, "windows_reset":result["windowsReset"], "message":message
        })),
    )
        .into_response()
}

fn usage_cache_key(provider: &str, access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    format!("{provider}:{}", hex::encode(digest))
}

fn parse_reset_time(value: &Value) -> Value {
    let timestamp = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()));
    if let Some(timestamp) = timestamp {
        let seconds = if timestamp.unsigned_abs() >= 1_000_000_000_000 {
            timestamp / 1000
        } else {
            timestamp
        };
        return chrono::DateTime::from_timestamp(seconds, 0)
            .map(|date| json!(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)))
            .unwrap_or(Value::Null);
    }
    let Some(value) = value.as_str() else {
        return Value::Null;
    };
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|date| {
            json!(
                date.with_timezone(&chrono::Utc)
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            )
        })
        .unwrap_or(Value::Null)
}

fn node_usage_fallback() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [("x-9router-fallback", "node")],
        Json(json!({"error":{"message":"Usage provider is not handled by the Rust gateway"}})),
    )
        .into_response()
}

async fn fetch_claude_usage(state: &AppState, access_token: &str) -> Result<Option<Value>, String> {
    let response = state
        .http
        .get("https://api.anthropic.com/api/oauth/usage?cedar_ember=1")
        .bearer_auth(access_token)
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("anthropic-version", "2023-06-01")
        .header("user-agent", "claude-cli/2.1.280 (external, cli)")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Ok(None);
    }
    let data: Value = response.json().await.map_err(|error| error.to_string())?;
    Ok(Some(parse_claude_usage(&data)))
}

fn parse_claude_usage(data: &Value) -> Value {
    let mut quotas = serde_json::Map::new();
    let mut add_quota = |name: String, utilization: f64, resets_at: &Value| {
        let used = utilization;
        let remaining = (100.0 - used).max(0.0);
        quotas.insert(
            name,
            json!({
                "used":used,
                "total":100,
                "remaining":remaining,
                "remainingPercentage":remaining,
                "resetAt":parse_reset_time(resets_at),
                "unlimited":false
            }),
        );
    };
    let mut add_window = |name: String, window: &Value| {
        if let Some(utilization) = window["utilization"].as_f64() {
            add_quota(name, utilization, &window["resets_at"]);
        }
    };
    add_window("session (5h)".into(), &data["five_hour"]);
    add_window("weekly (7d)".into(), &data["seven_day"]);
    if let Some(object) = data.as_object() {
        for (key, window) in object {
            if let Some(model) = key.strip_prefix("seven_day_") {
                if model != "" {
                    add_window(format!("weekly {model} (7d)"), window);
                }
            }
        }
    }
    if let Some(limits) = data["limits"].as_array() {
        for limit in limits {
            if limit["kind"] != "weekly_scoped" {
                continue;
            }
            let model = limit["scope"]["model"]["display_name"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            let Some(percent) = limit["percent"].as_f64() else {
                continue;
            };
            if !model.is_empty() {
                add_quota(
                    format!("weekly {model} (7d)"),
                    percent.clamp(0.0, 100.0),
                    &limit["resets_at"],
                );
            }
        }
    }
    json!({
        "plan":"Claude Code",
        "extraUsage":data.get("extra_usage").cloned().unwrap_or(Value::Null),
        "resetCredits":parse_claude_reset_grants(&data["cedar_ember"]),
        "quotas":quotas
    })
}

fn parse_claude_reset_grants(block: &Value) -> Value {
    let Some(grants) = block["grants"]
        .as_array()
        .filter(|_| block["eligible"] == true)
    else {
        return Value::Null;
    };
    let usable: Vec<&Value> = grants
        .iter()
        .filter(|grant| {
            grant["id"].as_str().is_some()
                && grant["paused"] != true
                && grant["resets_left"].as_f64().unwrap_or(0.0) > 0.0
        })
        .collect();
    let next = usable
        .iter()
        .find(|grant| grant["id"] == block["next_grant_id"])
        .or_else(|| usable.first())
        .copied();
    let available: f64 = usable
        .iter()
        .map(|grant| grant["resets_left"].as_f64().unwrap_or(0.0))
        .sum();
    json!({
        "availableCount":available,
        "nextGrantId":next.and_then(|grant| grant["id"].as_str()),
        "expiresAt":next.and_then(|grant| grant["ends_at"].as_str()),
        "clears":next.map(|grant| grant["clears"].clone()).unwrap_or_else(|| json!([])),
        "cooldownUntil":block.get("cooldown_until").cloned().unwrap_or(Value::Null),
        "weeklyResetsAt":block.get("weekly_resets_at").cloned().unwrap_or(Value::Null),
        "grants":grants.iter().filter(|grant| grant["id"].as_str().is_some()).map(|grant| json!({
            "id":grant["id"],
            "label":grant.get("label").and_then(Value::as_str).unwrap_or(""),
            "resetsLeft":grant["resets_left"].as_f64().unwrap_or(0.0),
            "resetsTotal":grant["resets_total"].as_f64().unwrap_or(0.0),
            "startsAt":grant.get("starts_at").cloned().unwrap_or(Value::Null),
            "endsAt":grant.get("ends_at").cloned().unwrap_or(Value::Null),
            "clears":grant.get("clears").filter(|value| value.is_array()).cloned().unwrap_or_else(|| json!([])),
            "paused":grant["paused"] == true,
            "usableNow":grant["usable_now"] == true,
            "useRequiresLimit":grant["use_requires_limit"] != false
        })).collect::<Vec<_>>()
    })
}

async fn fetch_codex_usage(state: &AppState, access_token: &str) -> Result<Option<Value>, String> {
    let response = state
        .http
        .get("https://chatgpt.com/backend-api/wham/usage")
        .bearer_auth(access_token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let data: Value = response.json().await.map_err(|error| error.to_string())?;
    Ok(Some(parse_codex_usage(&data)))
}

fn parse_codex_usage(data: &Value) -> Value {
    let normal = data
        .get("rate_limit")
        .or_else(|| data.get("rate_limits"))
        .or_else(|| data.pointer("/rate_limits_by_limit_id/codex"))
        .unwrap_or(&Value::Null);
    let review = data
        .get("code_review_rate_limit")
        .or_else(|| data.get("review_rate_limit"))
        .or_else(|| data.pointer("/rate_limits_by_limit_id/code_review"))
        .or_else(|| data.pointer("/rate_limits_by_limit_id/codex_review"))
        .or_else(|| data.pointer("/rate_limits_by_limit_id/review"))
        .or_else(|| {
            data.get("additional_rate_limits")
                .and_then(Value::as_array)
                .and_then(|limits| {
                    limits.iter().find(|limit| {
                        let id = limit
                            .get("limit_name")
                            .or_else(|| limit.get("metered_feature"))
                            .or_else(|| limit.get("id"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_lowercase();
                        id.contains("review")
                    })
                })
        })
        .unwrap_or(&Value::Null);
    let spark = data
        .get("spark_rate_limit")
        .or_else(|| data.get("gpt_5_3_codex_spark_rate_limit"))
        .or_else(|| data.pointer("/rate_limits_by_limit_id/gpt-5.3-codex-spark"))
        .or_else(|| data.pointer("/rate_limits_by_limit_id/gpt_5_3_codex_spark"))
        .or_else(|| data.pointer("/rate_limits_by_limit_id/spark"))
        .or_else(|| {
            data.get("additional_rate_limits")
                .and_then(Value::as_array)
                .and_then(|limits| {
                    limits.iter().find(|limit| {
                        let id = limit
                            .get("limit_name")
                            .or_else(|| limit.get("metered_feature"))
                            .or_else(|| limit.get("id"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_lowercase();
                        id.contains("spark") || id.contains("5.3-codex-spark")
                    })
                })
        })
        .unwrap_or(&Value::Null);
    let mut quotas = serde_json::Map::new();
    append_codex_quotas(&mut quotas, "", normal);
    append_codex_quotas(&mut quotas, "review", review);
    append_codex_quotas(&mut quotas, "spark", spark);
    json!({
        "plan":data.get("plan_type").and_then(Value::as_str).or_else(|| data.pointer("/summary/plan").and_then(Value::as_str)).unwrap_or("unknown"),
        "limitReached":codex_rate_limit(normal).get("limit_reached").and_then(Value::as_bool).unwrap_or(false),
        "reviewLimitReached":codex_rate_limit(review).get("limit_reached").and_then(Value::as_bool).unwrap_or(false),
        "sparkLimitReached":codex_rate_limit(spark).get("limit_reached").and_then(Value::as_bool).unwrap_or(false),
        "resetCredits":{"availableCount":data.pointer("/rate_limit_reset_credits/available_count").and_then(Value::as_f64).unwrap_or(0.0).max(0.0)},
        "quotas":quotas
    })
}

fn codex_rate_limit(snapshot: &Value) -> &Value {
    snapshot
        .get("rate_limit")
        .filter(|value| value.is_object())
        .unwrap_or(snapshot)
}

fn append_codex_quotas(
    quotas: &mut serde_json::Map<String, Value>,
    prefix: &str,
    snapshot: &Value,
) {
    let rate_limit = codex_rate_limit(snapshot);
    for (key, window) in [
        (
            if prefix.is_empty() {
                "session".into()
            } else {
                format!("{prefix}_session")
            },
            rate_limit
                .get("primary_window")
                .or_else(|| rate_limit.get("primary")),
        ),
        (
            if prefix.is_empty() {
                "weekly".into()
            } else {
                format!("{prefix}_weekly")
            },
            rate_limit
                .get("secondary_window")
                .or_else(|| rate_limit.get("secondary")),
        ),
    ] {
        if let Some(window) = window {
            let used = window
                .get("used_percent")
                .or_else(|| window.get("percent_used"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .clamp(0.0, 100.0);
            let reset = window
                .get("reset_at")
                .or_else(|| window.get("resets_at"))
                .or_else(|| window.get("resetAt"))
                .map(parse_reset_time)
                .unwrap_or(Value::Null);
            quotas.insert(key, json!({"used":used,"total":100,"remaining":100.0-used,"resetAt":reset,"unlimited":false}));
        }
    }
}

async fn api_usage_stream(
    State(s): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = futures_util::stream::unfold(
        (s, tokio::time::interval(std::time::Duration::from_secs(10))),
        |(state, mut interval)| async move {
            interval.tick().await;
            let event = match api_usage_stats(
                State(state.clone()),
                OriginalUri(axum::http::Uri::from_static("/api/usage/stats?period=7d")),
            )
            .await
            {
                Ok(Json(stats)) => Event::default().data(stats.to_string()),
                Err(_) => {
                    Event::default().data(json!({"error":"Usage stats unavailable"}).to_string())
                }
            };
            Some((Ok(event), (state, interval)))
        },
    );
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(25))
            .text("ping"),
    )
}

async fn api_usage_details(
    State(s): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let page = query_int(uri.query(), "page").unwrap_or(1);
    let page_size = query_int(uri.query(), "pageSize").unwrap_or(20);
    if page < 1 {
        return Err(ApiError::bad_request("Page must be >= 1"));
    }
    if !(1..=100).contains(&page_size) {
        return Err(ApiError::bad_request("PageSize must be between 1 and 100"));
    }
    let rows = sqlx::query("SELECT id,timestamp,provider,model,connectionId,status,data FROM requestDetails ORDER BY timestamp DESC LIMIT ? OFFSET ?")
        .bind(page_size).bind((page-1)*page_size).fetch_all(&s.db).await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requestDetails")
        .fetch_one(&s.db)
        .await?;
    let details: Vec<Value> = rows.into_iter().map(|r| {
        let mut data: Value = r.try_get::<String,_>("data").ok().and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_else(|| json!({}));
        if let Some(o) = data.as_object_mut() { for key in ["request","providerRequest","providerResponse","response"] { if o.contains_key(key) { o.insert(key.into(), json!({"redacted":true})); } } }
        json!({"id":r.try_get::<String,_>("id").unwrap_or_default(),"timestamp":r.try_get::<String,_>("timestamp").unwrap_or_default(),"provider":r.try_get::<Option<String>,_>("provider").ok().flatten(),"model":r.try_get::<Option<String>,_>("model").ok().flatten(),"connectionId":r.try_get::<Option<String>,_>("connectionId").ok().flatten(),"status":r.try_get::<Option<String>,_>("status").ok().flatten(),"details":data})
    }).collect();
    Ok(Json(
        json!({"details":details,"total":total,"page":page,"pageSize":page_size,"totalPages":(total + page_size - 1)/page_size}),
    ))
}

fn query_int(query: Option<&str>, key: &str) -> Option<i64> {
    query?.split('&').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k == key).then(|| v.parse().ok()).flatten()
    })
}

async fn api_list_proxy_pools(
    State(s): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let active_filter = uri
        .query()
        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("isActive=")));
    let rows = match active_filter {
        Some("true") => {
            sqlx::query("SELECT * FROM proxyPools WHERE isActive=1 ORDER BY updatedAt DESC")
                .fetch_all(&s.db)
                .await?
        }
        Some("false") => {
            sqlx::query("SELECT * FROM proxyPools WHERE isActive=0 ORDER BY updatedAt DESC")
                .fetch_all(&s.db)
                .await?
        }
        _ => {
            sqlx::query("SELECT * FROM proxyPools ORDER BY updatedAt DESC")
                .fetch_all(&s.db)
                .await?
        }
    };
    let include_usage = uri
        .query()
        .is_some_and(|q| q.split('&').any(|p| p == "includeUsage=true"));
    let pools: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let mut value: Value = row
                .try_get::<String, _>("data")
                .ok()
                .and_then(|v| serde_json::from_str(&v).ok())
                .unwrap_or_else(|| json!({}));
            let id: String = row.try_get("id").unwrap_or_default();
            value["id"] = json!(id);
            value["isActive"] = json!(row.try_get::<i64, _>("isActive").unwrap_or(0) == 1);
            value["testStatus"] = row
                .try_get::<Option<String>, _>("testStatus")
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null);
            value["createdAt"] = json!(row.try_get::<String, _>("createdAt").unwrap_or_default());
            value["updatedAt"] = json!(row.try_get::<String, _>("updatedAt").unwrap_or_default());
            value
        })
        .collect();
    if include_usage {
        let connections = sqlx::query("SELECT data FROM providerConnections")
            .fetch_all(&s.db)
            .await?;
        let mut counts = std::collections::HashMap::<String, i64>::new();
        for row in connections {
            let raw: String = row.try_get("data").unwrap_or_default();
            let data: Value = serde_json::from_str(&raw).unwrap_or_default();
            if let Some(id) = data["providerSpecificData"]["proxyPoolId"].as_str() {
                *counts.entry(id.to_string()).or_default() += 1;
            }
        }
        let enriched: Vec<Value> = pools
            .into_iter()
            .map(|mut pool| {
                let id = pool["id"].as_str().unwrap_or_default();
                pool["boundConnectionCount"] = json!(counts.get(id).copied().unwrap_or(0));
                pool
            })
            .collect();
        return Ok(Json(json!({"proxyPools":enriched})));
    }
    Ok(Json(json!({"proxyPools":pools})))
}

async fn api_create_proxy_pool(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    authorize(&s, &headers).await?;
    let name = body["name"].as_str().unwrap_or_default().trim();
    let proxy_url = body["proxyUrl"].as_str().unwrap_or_default().trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("Name is required"));
    }
    if proxy_url.is_empty() {
        return Err(ApiError::bad_request("Proxy URL is required"));
    }
    let pool = build_proxy_pool(body, None);
    save_proxy_pool(&s.db, &pool).await?;
    Ok((StatusCode::CREATED, Json(json!({"proxyPool":pool}))))
}

async fn api_get_proxy_pool(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let pool = read_proxy_pool(&s.db, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Proxy pool not found"))?;
    Ok(Json(json!({"proxyPool":pool})))
}

async fn api_update_proxy_pool(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers).await?;
    let existing = read_proxy_pool(&s.db, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Proxy pool not found"))?;
    let mut merged = existing;
    if let Some(obj) = body.as_object() {
        for (k, v) in obj {
            if k == "name" && v.as_str().unwrap_or_default().trim().is_empty() {
                return Err(ApiError::bad_request("Name is required"));
            }
            if k == "proxyUrl" && v.as_str().unwrap_or_default().trim().is_empty() {
                return Err(ApiError::bad_request("Proxy URL is required"));
            }
            merged[k] = v.clone();
        }
    }
    merged["updatedAt"] = json!(chrono::Utc::now().to_rfc3339());
    save_proxy_pool(&s.db, &merged).await?;
    Ok(Json(json!({"proxyPool":merged})))
}

async fn api_delete_proxy_pool(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers).await?;
    let Some(_) = read_proxy_pool(&s.db, &id).await? else {
        return Err(ApiError::not_found("Proxy pool not found"));
    };
    let connections = sqlx::query("SELECT data FROM providerConnections")
        .fetch_all(&s.db)
        .await?;
    let mut count = 0;
    for row in connections {
        let raw: String = sqlx::Row::try_get(&row, "data").unwrap_or_default();
        let data: Value = serde_json::from_str(&raw).unwrap_or_default();
        if data["providerSpecificData"]["proxyPoolId"].as_str() == Some(&id) {
            count += 1;
        }
    }
    if count > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("Proxy pool is currently in use ({count} connections)"),
        ));
    }
    sqlx::query("DELETE FROM proxyPools WHERE id=?")
        .bind(id)
        .execute(&s.db)
        .await?;
    Ok(Json(json!({"success":true})))
}

async fn api_test_proxy_pool(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers).await?;
    let mut pool = read_proxy_pool(&s.db, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Proxy pool not found"))?;
    let proxy_url = pool["proxyUrl"].as_str().unwrap_or_default();
    let start = std::time::Instant::now();
    let response = if matches!(
        pool["type"].as_str().unwrap_or("http"),
        "vercel" | "cloudflare" | "deno" | "netlify"
    ) {
        s.http
            .get(proxy_url)
            .header("x-relay-target", "https://httpbin.org")
            .header("x-relay-path", "/get")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
    } else {
        match reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::all(proxy_url)
                    .map_err(|e| ApiError::bad_request(format!("Invalid proxy URL: {e}")))?,
            )
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(client) => client.get("https://httpbin.org/get").send().await,
            Err(e) => Err(e),
        }
    };
    let elapsed = start.elapsed().as_millis() as u64;
    let now = chrono::Utc::now().to_rfc3339();
    let (ok, status, status_text, error) = match response {
        Ok(r) => {
            let status = r.status();
            (
                status.is_success(),
                status.as_u16(),
                status.canonical_reason().map(str::to_string),
                None,
            )
        }
        Err(e) => (false, 500, None, Some(e.to_string())),
    };
    pool["testStatus"] = json!(if ok { "active" } else { "error" });
    pool["lastTestedAt"] = json!(now);
    pool["lastError"] = if ok {
        Value::Null
    } else {
        json!(
            error
                .clone()
                .unwrap_or_else(|| format!("Proxy test failed with status {status}"))
        )
    };
    pool["isActive"] = json!(ok);
    pool["updatedAt"] = json!(now);
    save_proxy_pool(&s.db, &pool).await?;
    Ok(Json(
        json!({"ok":ok,"status":status,"statusText":status_text,"error":error,"elapsedMs":elapsed,"testedAt":now}),
    ))
}

fn build_proxy_pool(body: Value, id: Option<String>) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({"id":id.unwrap_or_else(||uuid::Uuid::new_v4().to_string()),"name":body["name"].as_str().unwrap_or_default().trim(),"proxyUrl":body["proxyUrl"].as_str().unwrap_or_default().trim(),"noProxy":body["noProxy"].as_str().unwrap_or_default(),"type":if ["http","vercel","cloudflare","deno","netlify"].contains(&body["type"].as_str().unwrap_or("")){body["type"].clone()}else{json!("http")},"isActive":body.get("isActive").and_then(Value::as_bool).unwrap_or(true),"strictProxy":body["strictProxy"]==true,"testStatus":"unknown","lastTestedAt":null,"lastError":null,"createdAt":now,"updatedAt":now})
}

async fn read_proxy_pool(db: &SqlitePool, id: &str) -> Result<Option<Value>, ApiError> {
    use sqlx::Row;
    let row = sqlx::query("SELECT * FROM proxyPools WHERE id=?")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| {
        let mut v: Value = r
            .try_get::<String, _>("data")
            .ok()
            .and_then(|x| serde_json::from_str(&x).ok())
            .unwrap_or_else(|| json!({}));
        v["id"] = json!(r.try_get::<String, _>("id").unwrap_or_default());
        v["isActive"] = json!(r.try_get::<i64, _>("isActive").unwrap_or(0) == 1);
        v["testStatus"] = r
            .try_get::<Option<String>, _>("testStatus")
            .ok()
            .flatten()
            .map(Value::String)
            .unwrap_or(Value::Null);
        v["createdAt"] = json!(r.try_get::<String, _>("createdAt").unwrap_or_default());
        v["updatedAt"] = json!(r.try_get::<String, _>("updatedAt").unwrap_or_default());
        v
    }))
}

async fn save_proxy_pool(db: &SqlitePool, pool: &Value) -> Result<(), ApiError> {
    let id = pool["id"].as_str().unwrap_or_default();
    let active = pool["isActive"].as_bool().unwrap_or(true);
    let status = pool["testStatus"].as_str();
    let created = pool["createdAt"].as_str().unwrap_or_default();
    let updated = pool["updatedAt"].as_str().unwrap_or_default();
    let mut data = pool.clone();
    if let Some(obj) = data.as_object_mut() {
        for k in ["id", "isActive", "testStatus", "createdAt", "updatedAt"] {
            obj.remove(k);
        }
    }
    sqlx::query("INSERT INTO proxyPools(id,isActive,testStatus,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET isActive=excluded.isActive,testStatus=excluded.testStatus,data=excluded.data,updatedAt=excluded.updatedAt").bind(id).bind(if active{1}else{0}).bind(status).bind(data.to_string()).bind(created).bind(updated).execute(db).await?;
    Ok(())
}

async fn api_translator_console_logs(State(state): State<AppState>) -> Json<Value> {
    Json(json!({"success":true,"logs":state.console_logs.snapshot()}))
}

async fn api_translator_clear_console_logs(State(state): State<AppState>) -> Json<Value> {
    state.console_logs.clear();
    Json(json!({"success":true}))
}

async fn api_translator_console_log_stream(State(state): State<AppState>) -> Response {
    let receiver = state.console_logs.subscribe();
    let initial_logs = state.console_logs.snapshot();
    let initial = futures_util::stream::once(async move {
        Ok::<_, std::convert::Infallible>(
            Event::default().data(json!({"type":"init","logs":initial_logs}).to_string()),
        )
    });
    let log_buffer = state.console_logs;
    let updates =
        futures_util::stream::unfold((receiver, log_buffer), |(mut receiver, logs)| async move {
            loop {
                let event = match receiver.recv().await {
                    Ok(ConsoleLogEvent::Line(line)) => {
                        Event::default().data(json!({"type":"line","line":line}).to_string())
                    }
                    Ok(ConsoleLogEvent::Clear) => {
                        Event::default().data(json!({"type":"clear"}).to_string())
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => Event::default()
                        .data(json!({"type":"init","logs":logs.snapshot()}).to_string()),
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                };
                return Some((Ok::<_, std::convert::Infallible>(event), (receiver, logs)));
            }
        });
    let mut response = Sse::new(initial.chain(updates))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(25)))
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    response
}

fn translator_file(name: &str) -> bool {
    [
        "1_req_client.json",
        "2_req_source.json",
        "3_req_openai.json",
        "4_req_target.json",
        "5_res_provider.txt",
        "6_res_openai.txt",
        "7_res_client.txt",
        "7_res_client.json",
    ]
    .contains(&name)
}

async fn api_translator_load(
    State(_s): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let file = uri
        .query()
        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("file=")))
        .unwrap_or("");
    if !translator_file(file) {
        return Err(ApiError::bad_request("Invalid file name"));
    }
    let path = std::env::current_dir()
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .join("logs")
        .join("translator")
        .join(file);
    let content = tokio::fs::read_to_string(path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ApiError::not_found("File not found")
        } else {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;
    Ok(Json(json!({"success":true,"content":content})))
}

async fn api_translator_save(
    State(_s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    authorize_dashboard_header(&headers)?;
    let file = body["file"].as_str().unwrap_or("");
    let content = body["content"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("File and content required"))?;
    if !translator_file(file) {
        return Err(ApiError::bad_request("Invalid file name"));
    }
    let dir = std::env::current_dir()
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .join("logs")
        .join("translator");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tokio::fs::write(dir.join(file), content)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"success":true})))
}

fn authorize_dashboard_header(headers: &HeaderMap) -> Result<(), ApiError> {
    if let Ok(Some(expected)) = std::env::var("NINEROUTER_API_KEY").map(Some) {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()));
        if provided != Some(expected.as_str()) {
            return Err(ApiError::unauthorized("Missing or invalid API key"));
        }
    }
    Ok(())
}

async fn api_translator_translate(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers).await?;
    let step = body["step"]
        .as_i64()
        .ok_or_else(|| ApiError::bad_request("Step and body required"))?;
    let input = body.get("body").cloned().unwrap_or(Value::Null);
    if input.is_null() {
        return Err(ApiError::bad_request("Step and body required"));
    }
    let client_body = input.get("body").cloned().unwrap_or_else(|| input.clone());
    if step == 1 {
        let requested = client_body["model"].as_str().unwrap_or_default();
        let target = resolve_targets(&s.db, requested)
            .await?
            .into_iter()
            .next()
            .unwrap_or_else(|| requested.into());
        let (provider, model) = target.split_once('/').unwrap_or(("", requested));
        let target_format = if provider == "anthropic" || provider.starts_with("claude") {
            "anthropic"
        } else {
            "openai"
        };
        let source =
            if client_body.get("system").is_some() || client_body.get("max_tokens").is_some() {
                "anthropic"
            } else {
                "openai"
            };
        return Ok(Json(
            json!({"success":true,"result":{"provider":provider,"model":model,"sourceFormat":source,"targetFormat":target_format}}),
        ));
    }
    if step == 2 {
        let requested = client_body["model"].as_str().unwrap_or_default();
        let target = resolve_targets(&s.db, requested)
            .await?
            .into_iter()
            .next()
            .unwrap_or_else(|| requested.into());
        let (provider, model) = target.split_once('/').unwrap_or(("", requested));
        let source =
            if client_body.get("system").is_some() || client_body.get("max_tokens").is_some() {
                "anthropic"
            } else {
                "openai"
            };
        let openai = if source == "openai" {
            client_body.clone()
        } else {
            translate_request(&client_body, "anthropic", "openai")
        };
        let mut result = openai.clone();
        result["model"] = json!(model);
        if result["stream"].is_null() {
            result["stream"] = json!(true);
        }
        let _ = provider;
        return Ok(Json(json!({"success":true,"result":{"body":result}})));
    }
    if step == 3 {
        let provider = body["provider"]
            .as_str()
            .ok_or_else(|| ApiError::bad_request("provider and model required"))?;
        let model = body["model"]
            .as_str()
            .ok_or_else(|| ApiError::bad_request("provider and model required"))?;
        let connection = store::list_routing_accounts(&s.db)
            .await?
            .into_iter()
            .find(|candidate| candidate.id == provider)
            .ok_or_else(|| {
                ApiError::bad_request(format!("No active connection for provider: {provider}"))
            })?;
        let target_format = connection.api_format.as_str();
        let mut result = if target_format == "openai" {
            client_body.clone()
        } else {
            translate_request(&client_body, "openai", "anthropic")
        };
        result["model"] = json!(model);
        let path = if target_format == "anthropic" {
            "messages"
        } else {
            "chat/completions"
        };
        let upstream_path = format!("{}/{}", connection.api_path_prefix.trim_matches('/'), path);
        let url = endpoint_url(&connection.base_url, &upstream_path, None)?;
        let mut headers = serde_json::Map::new();
        if target_format == "anthropic" {
            headers.insert("anthropic-version".into(), json!("2023-06-01"));
            if connection.auth_type == "oauth" {
                headers.insert(
                    "authorization".into(),
                    json!(format!("Bearer {}", connection.api_key)),
                );
                headers.insert(
                    "anthropic-beta".into(),
                    json!("oauth-2025-04-20,claude-code-20250219"),
                );
            } else {
                headers.insert("x-api-key".into(), json!(connection.api_key));
            }
        } else {
            headers.insert(
                "authorization".into(),
                json!(format!("Bearer {}", connection.api_key)),
            );
        }
        return Ok(Json(
            json!({"success":true,"result":{"url":url,"headers":headers,"body":result}}),
        ));
    }
    Err(ApiError::bad_request("Invalid step (1-3)"))
}

async fn api_translator_send(
    State(state): State<AppState>,
    OriginalUri(_uri): OriginalUri,
    mut headers: HeaderMap,
    Json(input): Json<Value>,
) -> Result<Response, ApiError> {
    let provider = input["provider"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("provider, model, and body required"))?;
    let model = input["model"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("provider, model, and body required"))?;
    let mut body = input
        .get("body")
        .cloned()
        .ok_or_else(|| ApiError::bad_request("provider, model, and body required"))?;
    if !body.is_object() {
        return Err(ApiError::bad_request("body must be a JSON object"));
    }
    let requested_model = if model.contains('/') {
        model.to_string()
    } else {
        format!("{provider}/{model}")
    };
    body["model"] = json!(requested_model);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let anthropic_request = body.get("system").is_some() || body.get("max_tokens").is_some();
    let path = if anthropic_request {
        "messages"
    } else {
        "chat/completions"
    };
    let uri = if anthropic_request {
        axum::http::Uri::from_static("/v1/messages")
    } else {
        axum::http::Uri::from_static("/v1/chat/completions")
    };
    proxy(
        State(state),
        OriginalUri(uri),
        Path(path.to_string()),
        Method::POST,
        headers,
        Bytes::from(serde_json::to_vec(&body).map_err(|e| ApiError::bad_request(e.to_string()))?)
            .into(),
    )
    .await
}

async fn api_media_tts_voices(
    State(s): State<AppState>,
    Path(route_provider): Path<String>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let query = uri.query().unwrap_or("");
    let lang = query_value(query, "lang");
    let provider =
        if route_provider == "minimax" && query_value(query, "provider") == Some("minimax-cn") {
            "minimax-cn"
        } else {
            route_provider.as_str()
        };
    let row=sqlx::query("SELECT data FROM providerConnections WHERE provider=? AND isActive=1 ORDER BY COALESCE(priority,999),updatedAt LIMIT 1").bind(provider).fetch_optional(&s.db).await?;
    let Some(row) = row else {
        return Err(ApiError::bad_request(format!(
            "No {provider} connection found"
        )));
    };
    let data: Value = serde_json::from_str(&row.try_get::<String, _>("data").unwrap_or_default())
        .unwrap_or_default();
    let key = data["apiKey"]
        .as_str()
        .or_else(|| data["accessToken"].as_str())
        .unwrap_or_default();
    if key.is_empty() {
        return Err(ApiError::bad_request(format!(
            "No {provider} connection found"
        )));
    }
    let raw = match provider {
        "deepgram" => {
            s.http
                .get("https://api.deepgram.com/v1/models")
                .header(header::AUTHORIZATION, format!("Token {key}"))
                .send()
                .await
        }
        "elevenlabs" => {
            s.http
                .get("https://api.elevenlabs.io/v1/voices")
                .header("xi-api-key", key)
                .send()
                .await
        }
        "inworld" => {
            s.http
                .get("https://api.inworld.ai/tts/v1/voices")
                .header(header::AUTHORIZATION, format!("Basic {key}"))
                .send()
                .await
        }
        "minimax" | "minimax-cn" => {
            s.http
                .post(if provider == "minimax-cn" {
                    "https://api.minimaxi.com/v1/get_voice"
                } else {
                    "https://api.minimax.io/v1/get_voice"
                })
                .bearer_auth(key)
                .json(&json!({"voice_type":query_value(query,"voice_type").unwrap_or("all")}))
                .send()
                .await
        }
        _ => {
            return Err(ApiError::bad_request(format!(
                "Provider '{provider}' does not support voice listing"
            )));
        }
    }
    .map_err(|e| ApiError::upstream(e.to_string()))?;
    if !raw.status().is_success() {
        let status = raw.status().as_u16();
        let text = raw.text().await.unwrap_or_default();
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!(
                "{provider} API {status}: {}",
                if text.is_empty() { "Failed" } else { &text }
            ),
        ));
    }
    let payload: Value = raw
        .json()
        .await
        .map_err(|e| ApiError::upstream(e.to_string()))?;
    let mut by_lang = serde_json::Map::<String, Value>::new();
    let mut add_voice = |code: String, voice: Value| {
        let entry = by_lang
            .entry(code.clone())
            .or_insert_with(|| json!({"code":code,"name":code,"voices":[]}));
        if let Some(array) = entry["voices"].as_array_mut() {
            let id = voice["id"].as_str();
            if !array.iter().any(|v| v["id"].as_str() == id) {
                array.push(voice);
            }
        }
    };
    match provider {
        "deepgram" => {
            for item in payload["tts"].as_array().cloned().unwrap_or_default() {
                let id = item["canonical_name"]
                    .as_str()
                    .or(item["name"].as_str())
                    .unwrap_or("voice");
                let langs = item["languages"]
                    .as_array()
                    .cloned()
                    .filter(|a| !a.is_empty())
                    .unwrap_or_else(|| vec![json!(id.split('-').next_back().unwrap_or("en"))]);
                for l in langs {
                    let code = l.as_str().unwrap_or("en").to_string();
                    add_voice(
                        code.clone(),
                        json!({"id":id,"name":item["name"].as_str().unwrap_or(id),"gender":"","lang":code}),
                    );
                }
            }
        }
        "inworld" => {
            for item in payload["voices"].as_array().cloned().unwrap_or_default() {
                let id = item["voiceId"].as_str().unwrap_or("voice");
                let langs = item["languages"]
                    .as_array()
                    .cloned()
                    .filter(|a| !a.is_empty())
                    .unwrap_or_else(|| vec![json!("en")]);
                for l in langs {
                    let code = l.as_str().unwrap_or("en").to_string();
                    add_voice(
                        code.clone(),
                        json!({"id":id,"name":item["displayName"].as_str().unwrap_or(id),"gender":item["gender"].as_str().unwrap_or(""),"lang":code}),
                    );
                }
            }
        }
        "elevenlabs" => {
            for item in payload["voices"].as_array().cloned().unwrap_or_default() {
                let code = item["labels"]["language"]
                    .as_str()
                    .unwrap_or("en")
                    .to_string();
                let voice = json!({"id":item["voice_id"],"name":item["name"],"gender":item["labels"]["gender"].as_str().unwrap_or(""),"lang":code,"free_users_allowed":item["category"]=="premade"||item["is_owner"]==true});
                add_voice(code, voice);
                for verified in item["verified_languages"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                {
                    if let Some(code) = verified["language"].as_str() {
                        add_voice(
                            code.into(),
                            json!({"id":item["voice_id"],"name":item["name"],"gender":item["labels"]["gender"].as_str().unwrap_or(""),"lang":code,"free_users_allowed":item["category"]=="premade"||item["is_owner"]==true}),
                        );
                    }
                }
            }
        }
        "minimax" | "minimax-cn" => {
            let base = payload
                .get("base_resp")
                .or(payload.get("baseResp"))
                .cloned()
                .unwrap_or(json!({}));
            if base
                .get("status_code")
                .or(base.get("statusCode"))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                != 0
            {
                return Err(ApiError::upstream(
                    base["status_msg"]
                        .as_str()
                        .unwrap_or("MiniMax voice API error"),
                ));
            }
            for (group, label) in [
                ("system_voice", "System"),
                ("voice_cloning", "Cloned"),
                ("voice_generation", "Generated"),
                ("music_generation", "Music"),
            ] {
                for item in payload[group].as_array().cloned().unwrap_or_default() {
                    let id = item["voice_id"]
                        .as_str()
                        .or(item["voiceId"].as_str())
                        .unwrap_or("");
                    if id.is_empty() {
                        continue;
                    }
                    let code = if group == "system_voice" {
                        id.split('_').next().unwrap_or("Custom")
                    } else {
                        "Custom"
                    };
                    add_voice(
                        code.into(),
                        json!({"id":id,"name":format!("{}{}",item["voice_name"].as_str().or(item["voiceName"].as_str()).unwrap_or(id),if group=="system_voice"{String::new()}else{format!(" · {label}")}),"lang":code,"category":group}),
                    );
                }
            }
        }
        _ => {}
    }
    let mut languages: Vec<Value> = by_lang.values().cloned().collect();
    languages.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["name"].as_str().unwrap_or(""))
    });
    if let Some(lang) = lang {
        return Ok(Json(
            json!({"voices":by_lang.get(lang).and_then(|v|v["voices"].as_array()).cloned().unwrap_or_default()}),
        ));
    }
    Ok(Json(json!({"languages":languages,"byLang":by_lang})))
}

async fn api_tts_voices(State(state): State<AppState>, OriginalUri(uri): OriginalUri) -> Response {
    let query: HashMap<String, String> = uri
        .query()
        .and_then(|query| serde_urlencoded::from_str(query).ok())
        .unwrap_or_default();
    let provider = query
        .get("provider")
        .map(String::as_str)
        .unwrap_or("edge-tts");
    let lang_filter = query.get("lang").map(String::as_str);
    let supported = [
        "edge-tts",
        "local-device",
        "elevenlabs",
        "deepgram",
        "inworld",
    ];
    if !supported.contains(&provider) {
        return tts_voice_json_response(
            StatusCode::BAD_REQUEST,
            json!({"error":format!("Provider '{provider}' does not support voice listing")}),
        );
    }

    let voices = match provider {
        "edge-tts" => match fetch_edge_tts_voices(&state.http).await {
            Ok(voices) => voices,
            Err(error) => {
                return tts_voice_json_response(StatusCode::BAD_GATEWAY, json!({"error":error}));
            }
        },
        // The previous runtime's local-device adapter returns no voices on Linux,
        // which is the supported server platform for the Rust deployment.
        "local-device" => Vec::new(),
        _ => match fetch_provider_tts_voices(state, provider, lang_filter).await {
            Ok(voices) => voices,
            Err(error) => {
                let mut response = error.into_response();
                add_tts_cors_headers(response.headers_mut());
                return response;
            }
        },
    };

    let voices = voices
        .into_iter()
        .filter(|voice| lang_filter.is_none_or(|lang| voice["lang"] == lang))
        .collect::<Vec<_>>();
    let mut by_lang = serde_json::Map::<String, Value>::new();
    for voice in &voices {
        let lang = voice["lang"].as_str().unwrap_or_default();
        let entry = by_lang
            .entry(lang.to_owned())
            .or_insert_with(|| json!({"code":lang,"name":lang,"voices":[]}));
        entry["voices"].as_array_mut().unwrap().push(voice.clone());
    }
    let mut languages = by_lang.values().cloned().collect::<Vec<_>>();
    languages.sort_by(|left, right| {
        left["name"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["name"].as_str().unwrap_or_default())
    });
    tts_voice_json_response(
        StatusCode::OK,
        json!({"voices":voices,"languages":languages,"byLang":by_lang}),
    )
}

async fn api_v1_audio_voices(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let query: HashMap<String, String> = uri
        .query()
        .and_then(|query| serde_urlencoded::from_str(query).ok())
        .unwrap_or_default();
    let provider = query
        .get("provider")
        .map(String::as_str)
        .unwrap_or_default();
    let lang_filter = query.get("lang").map(String::as_str);
    if provider.is_empty()
        || ![
            "elevenlabs",
            "deepgram",
            "inworld",
            "edge-tts",
            "local-device",
        ]
        .contains(&provider)
    {
        return tts_voice_json_response(
            StatusCode::BAD_REQUEST,
            json!({"error":{"message":"provider must be one of: elevenlabs, deepgram, inworld, edge-tts, local-device","type":"invalid_request_error"}}),
        );
    }
    let result = match provider {
        "edge-tts" => fetch_edge_tts_voices(&state.http)
            .await
            .map_err(ApiError::upstream),
        "local-device" => Ok::<Vec<Value>, ApiError>(Vec::new()),
        _ => fetch_provider_tts_voices(state, provider, lang_filter).await,
    };
    let voices = match result {
        Ok(voices) => voices,
        Err(error) => {
            let message = error.message.clone();
            let mut response = error.into_response();
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            *response.body_mut() =
                Body::from(json!({"error":{"message":message,"type":"server_error"}}).to_string());
            add_tts_cors_headers(response.headers_mut());
            return response;
        }
    };
    let alias = match provider {
        "elevenlabs" => "el",
        "deepgram" => "dg",
        _ => provider,
    };
    let data = voices
        .into_iter()
        .filter(|voice| lang_filter.is_none_or(|lang| voice["lang"] == lang))
        .map(|voice| {
            json!({
                "id":voice["id"],
                "name":voice["name"],
                "lang":voice["lang"].as_str().unwrap_or_default(),
                "gender":voice["gender"].as_str().unwrap_or_default(),
                "model":format!("{alias}/{}",voice["id"].as_str().unwrap_or_default())
            })
        })
        .collect::<Vec<_>>();
    tts_voice_json_response(StatusCode::OK, json!({"object":"list","data":data}))
}

async fn fetch_provider_tts_voices(
    state: AppState,
    provider: &str,
    lang: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    let mut query = Vec::new();
    if let Some(lang) = lang {
        query.push(("lang", lang));
    }
    let query_string = serde_urlencoded::to_string(query)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let path_and_query = if query_string.is_empty() {
        format!("/api/media-providers/tts/{provider}/voices")
    } else {
        format!("/api/media-providers/tts/{provider}/voices?{query_string}")
    };
    let uri = path_and_query
        .parse()
        .map_err(|error: axum::http::uri::InvalidUri| ApiError::bad_request(error.to_string()))?;
    let Json(payload) =
        api_media_tts_voices(State(state), Path(provider.to_owned()), OriginalUri(uri)).await?;
    if let Some(voices) = payload["voices"].as_array() {
        return Ok(voices.clone());
    }
    Ok(payload["byLang"]
        .as_object()
        .into_iter()
        .flat_map(|langs| langs.values())
        .filter_map(|entry| entry["voices"].as_array())
        .flatten()
        .cloned()
        .collect())
}

async fn fetch_edge_tts_voices(client: &reqwest::Client) -> Result<Vec<Value>, String> {
    const VOICES_URL: &str = "https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/voices/list?trustedclienttoken=6A5AA1D4EAFF4E9FB37E23D68491D6F4";
    let response = client
        .get(VOICES_URL)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Edge TTS voices fetch failed: {}",
            response.status()
        ));
    }
    let raw: Vec<Value> = response.json().await.map_err(|error| error.to_string())?;
    Ok(raw
        .into_iter()
        .map(|voice| {
            let locale = voice["Locale"].as_str().unwrap_or_default();
            let (lang, country) = locale.split_once('-').unwrap_or((locale, ""));
            let name = voice["FriendlyName"]
                .as_str()
                .unwrap_or_else(|| voice["ShortName"].as_str().unwrap_or_default())
                .trim_start_matches("Microsoft ")
                .replace(" Online (Natural) - ", " (");
            json!({
                "id":voice["ShortName"],
                "name":name,
                "locale":locale,
                "lang":lang,
                "country":country,
                "countryName":country,
                "langName":lang,
                "gender":voice["Gender"].as_str().unwrap_or_default()
            })
        })
        .collect())
}

async fn api_tts_voices_options() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_tts_cors_headers(response.headers_mut());
    response
}

fn tts_voice_json_response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    add_tts_cors_headers(response.headers_mut());
    response
}

fn add_tts_cors_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k == key).then_some(v)
    })
}

async fn get_or_spawn_mcp(state: &AppState, plugin: &str) -> Result<McpEntry, ApiError> {
    if plugin != "browsermcp" {
        return Err(ApiError::not_found(format!("Unknown plugin: {plugin}")));
    }
    let mut entries = state.mcp_entries.lock().await;
    if let Some(entry) = entries.get(plugin) {
        let exited = entry
            .child
            .lock()
            .await
            .try_wait()
            .map_err(|e| ApiError::upstream(e.to_string()))?
            .is_some();
        if !exited {
            return Ok(entry.clone());
        }
        entries.remove(plugin);
    }
    let mut child = tokio::process::Command::new("npx")
        .args(["-y", "@browsermcp/mcp@latest"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start MCP plugin: {e}"),
            )
        })?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ApiError::upstream("MCP plugin stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ApiError::upstream("MCP plugin stdout unavailable"))?;
    let (messages, _) = tokio::sync::broadcast::channel(128);
    let entry = McpEntry {
        child: Arc::new(tokio::sync::Mutex::new(child)),
        stdin: Arc::new(tokio::sync::Mutex::new(stdin)),
        messages: messages.clone(),
        sessions: Arc::new(AtomicUsize::new(0)),
    };
    entries.insert(plugin.to_string(), entry.clone());
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) if !line.trim().is_empty() => {
                    let _ = messages.send(filter_mcp_frame(&line));
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    });
    Ok(entry)
}

fn filter_mcp_frame(raw: &str) -> String {
    const MAX_TEXT_CHARS: usize = 50_000;
    let Ok(mut frame) = serde_json::from_str::<Value>(raw) else {
        return raw.to_string();
    };
    let Some(content) = frame["result"]["content"].as_array_mut() else {
        return raw.to_string();
    };
    let mut changed = false;
    for item in content {
        if item["type"] == "text" {
            if let Some(text) = item["text"].as_str() {
                if text.chars().count() > MAX_TEXT_CHARS {
                    let preview: String = text.chars().take(MAX_TEXT_CHARS - 200).collect();
                    item["text"] = json!(format!(
                        "{preview}\n\n... [text truncated by 9Router MCP bridge]"
                    ));
                    changed = true;
                }
            }
        }
    }
    if changed {
        serde_json::to_string(&frame).unwrap_or_else(|_| raw.to_string())
    } else {
        raw.to_string()
    }
}

async fn api_mcp_sse(
    State(state): State<AppState>,
    Path(plugin): Path<String>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>>, ApiError>
{
    let entry = get_or_spawn_mcp(&state, &plugin).await?;
    entry.sessions.fetch_add(1, Ordering::AcqRel);
    let receiver = entry.messages.subscribe();
    let session_id = uuid::Uuid::new_v4();
    let guard = McpSessionGuard {
        state,
        plugin: plugin.clone(),
        sessions: entry.sessions.clone(),
        child: entry.child.clone(),
    };
    let endpoint = Event::default()
        .event("endpoint")
        .data(format!("/api/mcp/{plugin}/message?sessionId={session_id}"));
    let messages =
        futures_util::stream::unfold((receiver, guard), |(mut receiver, guard)| async move {
            loop {
                match receiver.recv().await {
                    Ok(message) => {
                        return Some((
                            Ok(Event::default().event("message").data(message)),
                            (receiver, guard),
                        ));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
    let stream = futures_util::stream::once(async move { Ok(endpoint) }).chain(messages);
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(25))
            .text("ping"),
    ))
}

async fn api_mcp_message(
    State(state): State<AppState>,
    Path(plugin): Path<String>,
    Json(message): Json<Value>,
) -> Result<StatusCode, ApiError> {
    if plugin != "browsermcp" {
        return Err(ApiError::not_found(format!("Unknown plugin: {plugin}")));
    }
    let entry = state
        .mcp_entries
        .lock()
        .await
        .get(&plugin)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("MCP bridge is not running: {plugin}"),
            )
        })?;
    let mut stdin = entry.stdin.lock().await;
    let mut frame =
        serde_json::to_vec(&message).map_err(|e| ApiError::bad_request(e.to_string()))?;
    frame.push(b'\n');
    use tokio::io::AsyncWriteExt;
    stdin
        .write_all(&frame)
        .await
        .map_err(|e| ApiError::upstream(e.to_string()))?;
    stdin
        .flush()
        .await
        .map_err(|e| ApiError::upstream(e.to_string()))?;
    Ok(StatusCode::ACCEPTED)
}

async fn api_usage_chart(
    State(s): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let period = uri
        .query()
        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("period=")))
        .unwrap_or("7d");
    if !["today", "24h", "7d", "30d", "60d", "all"].contains(&period) {
        return Err(ApiError::bad_request("Invalid period"));
    }
    if period == "all" {
        let daily = sqlx::query("SELECT dateKey,data FROM usageDaily ORDER BY dateKey")
            .fetch_all(&s.db)
            .await?;
        if !daily.is_empty() {
            let points = daily
                .into_iter()
                .map(|row| {
                    let date: String = row.try_get("dateKey").unwrap_or_default();
                    let day: Value = row
                        .try_get::<String, _>("data")
                        .ok()
                        .and_then(|v| serde_json::from_str(&v).ok())
                        .unwrap_or_else(|| json!({}));
                    let label = chrono::NaiveDate::parse_from_str(&date, "%Y-%m-%d")
                        .map(|d| d.format("%b %-d").to_string())
                        .unwrap_or(date);
                    json!({"label":label,"tokens":day["promptTokens"].as_i64().unwrap_or(0)+day["completionTokens"].as_i64().unwrap_or(0),"cost":day["cost"].as_f64().unwrap_or(0.0),"requests":day["requests"].as_i64().unwrap_or(0)})
                })
                .collect::<Vec<_>>();
            return Ok(Json(Value::Array(points)));
        }
    }
    let now = chrono::Utc::now();
    let hourly = period == "today" || period == "24h";
    let count = if hourly {
        24
    } else if period == "30d" {
        30
    } else if period == "60d" {
        60
    } else {
        7
    };
    let start = if period == "today" {
        now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc()
    } else if hourly {
        now - chrono::Duration::hours(24)
    } else {
        now - chrono::Duration::days(count)
    };
    let rows=sqlx::query("SELECT timestamp,promptTokens,completionTokens,cost FROM usageHistory WHERE timestamp >= ? ORDER BY timestamp") .bind(start.to_rfc3339()).fetch_all(&s.db).await?;
    let mut buckets: Vec<Value>=(0..count).map(|i| json!({"label":if hourly { format!("{:02}:00",(start + chrono::Duration::hours(i)).hour()) } else { (start + chrono::Duration::days(i)).format("%b %-d").to_string() },"tokens":0,"cost":0.0,"requests":0})).collect();
    for r in rows {
        let ts: String = r.try_get("timestamp").unwrap_or_default();
        let Ok(t) = chrono::DateTime::parse_from_rfc3339(&ts) else {
            continue;
        };
        let delta = t.with_timezone(&chrono::Utc) - start;
        let idx = if hourly {
            delta.num_hours()
        } else {
            delta.num_days()
        };
        if idx < 0 || idx >= count {
            continue;
        }
        let b = &mut buckets[idx as usize];
        b["tokens"] = json!(
            b["tokens"].as_i64().unwrap_or(0)
                + r.try_get::<i64, _>("promptTokens").unwrap_or(0)
                + r.try_get::<i64, _>("completionTokens").unwrap_or(0)
        );
        b["cost"] =
            json!(b["cost"].as_f64().unwrap_or(0.0) + r.try_get::<f64, _>("cost").unwrap_or(0.0));
        b["requests"] = json!(b["requests"].as_i64().unwrap_or(0) + 1);
    }
    Ok(Json(Value::Array(buckets)))
}

async fn api_get_pricing(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let mut merged =
        serde_json::from_str::<Value>(include_str!("../pricing.json")).unwrap_or(json!({}));
    let overrides = kv_map(&s.db, "pricing").await?;
    for (provider, models) in overrides {
        if let Some(models) = models.as_object() {
            let target = merged[&provider].as_object_mut();
            if let Some(target) = target {
                target.extend(models.clone());
            } else {
                merged[&provider] = Value::Object(models.clone());
            }
        }
    }
    Ok(Json(merged))
}
async fn api_patch_pricing(
    State(s): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let providers = body
        .as_object()
        .ok_or_else(|| ApiError::bad_request("Invalid pricing data format"))?;
    for (provider, models) in providers {
        let models = models.as_object().ok_or_else(|| {
            ApiError::bad_request(format!("Invalid pricing for provider: {provider}"))
        })?;
        for (model, pricing) in models {
            let fields = pricing.as_object().ok_or_else(|| {
                ApiError::bad_request(format!("Invalid pricing for model: {provider}/{model}"))
            })?;
            for (field, value) in fields {
                if !["input", "output", "cached", "reasoning", "cache_creation"]
                    .contains(&field.as_str())
                {
                    return Err(ApiError::bad_request(format!(
                        "Invalid pricing field: {field} for {provider}/{model}"
                    )));
                }
                if value.as_f64().is_none_or(|v| !v.is_finite() || v < 0.0) {
                    return Err(ApiError::bad_request(format!(
                        "Invalid pricing value for {field} in {provider}/{model}: must be non-negative number"
                    )));
                }
            }
        }
    }
    for (provider, models) in providers {
        let mut current =
            sqlx::query_scalar::<_, String>("SELECT value FROM kv WHERE scope='pricing' AND key=?")
                .bind(provider)
                .fetch_optional(&s.db)
                .await?
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
        if let Some(incoming) = models.as_object() {
            current.extend(incoming.clone());
        }
        kv_set(&s.db, "pricing", provider, &Value::Object(current)).await?;
    }
    api_get_pricing(State(s)).await
}
async fn api_delete_pricing(
    State(s): State<AppState>,
    OriginalUri(u): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let q = query_pairs(u.query().unwrap_or_default());
    let provider = q.get("provider");
    let model = q.get("model");
    match (provider, model) {
        (Some(provider), Some(model)) => {
            let mut current = sqlx::query_scalar::<_, String>(
                "SELECT value FROM kv WHERE scope='pricing' AND key=?",
            )
            .bind(provider)
            .fetch_optional(&s.db)
            .await?
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
            current.remove(model);
            if current.is_empty() {
                sqlx::query("DELETE FROM kv WHERE scope='pricing' AND key=?")
                    .bind(provider)
                    .execute(&s.db)
                    .await?;
            } else {
                kv_set(&s.db, "pricing", provider, &Value::Object(current)).await?;
            }
        }
        (Some(provider), None) => {
            sqlx::query("DELETE FROM kv WHERE scope='pricing' AND key=?")
                .bind(provider)
                .execute(&s.db)
                .await?;
        }
        _ => {
            sqlx::query("DELETE FROM kv WHERE scope='pricing'")
                .execute(&s.db)
                .await?;
        }
    }
    api_get_pricing(State(s)).await
}

// Dashboard APIs below deliberately use the same SQLite tables as the Node app,
// allowing the existing frontend and existing installations to keep their data.
async fn api_list_combos(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id,name,kind,models,createdAt,updatedAt FROM combos ORDER BY createdAt ASC",
    )
    .fetch_all(&s.db)
    .await?;
    let combos=rows.into_iter().map(|r|{
        let models=serde_json::from_str::<Value>(r.get::<String,_>("models").as_str()).unwrap_or(json!([]));
        json!({"id":r.get::<String,_>("id"),"name":r.get::<String,_>("name"),"kind":r.get::<Option<String>,_>("kind"),"models":models,"createdAt":r.get::<String,_>("createdAt"),"updatedAt":r.get::<String,_>("updatedAt")})
    }).collect::<Vec<_>>();
    Ok(Json(json!({"combos":combos})))
}

async fn combo_preset_items(db: &SqlitePool, source: &str) -> Result<Vec<Value>, ApiError> {
    if !matches!(source, "cursor" | "claude") {
        return Err(ApiError::bad_request("source must be 'cursor' or 'claude'"));
    }
    let rows = sqlx::query_scalar::<_, String>("SELECT name FROM combos")
        .fetch_all(db)
        .await?;
    let existing: std::collections::HashSet<String> = rows.into_iter().collect();
    let presets: Value =
        serde_json::from_str(include_str!("combo_presets.json")).unwrap_or_default();
    Ok(presets[source].as_array().into_iter().flatten().map(|item|{
        let name=item["name"].as_str().unwrap_or_default();
        json!({"name":name,"models":item["models"].as_array().cloned().unwrap_or_default(),"exists":existing.contains(name)})
    }).collect())
}

async fn api_combo_presets_get(
    State(s): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let source = query_value(uri.query().unwrap_or_default(), "source").unwrap_or_default();
    let items = combo_preset_items(&s.db, source).await?;
    let to_create = items.iter().filter(|item| item["exists"] == false).count();
    Ok(Json(
        json!({"source":source,"items":items,"toCreate":to_create,"toSkip":items.len()-to_create}),
    ))
}

async fn api_combo_presets_post(
    State(s): State<AppState>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let source = input
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let items = combo_preset_items(&s.db, source).await?;
    let mut created = Vec::new();
    let mut skipped = Vec::new();
    for item in items {
        let name = item["name"].as_str().unwrap_or_default();
        if item["exists"] == true {
            skipped.push(json!(name));
            continue;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let now = timestamp();
        let models = item["models"].as_array().cloned().unwrap_or_default();
        sqlx::query(
            "INSERT INTO combos(id,name,kind,models,createdAt,updatedAt) VALUES(?,?,NULL,?,?,?)",
        )
        .bind(&id)
        .bind(name)
        .bind(Value::Array(models.clone()).to_string())
        .bind(&now)
        .bind(&now)
        .execute(&s.db)
        .await?;
        created.push(json!({"id":id,"name":name,"kind":null,"models":models,"createdAt":now,"updatedAt":now}));
    }
    Ok(Json(
        json!({"source":source,"created":created,"skipped":skipped,"createdCount":created.len(),"skippedCount":skipped.len()}),
    ))
}

async fn api_get_combo(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query("SELECT id,name,kind,models,createdAt,updatedAt FROM combos WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.db)
        .await?
        .ok_or_else(|| ApiError::not_found("Combo not found"))?;
    use sqlx::Row;
    let models: Value =
        serde_json::from_str(row.get::<String, _>("models").as_str()).unwrap_or(json!([]));
    Ok(Json(
        json!({"id":row.get::<String,_>("id"),"name":row.get::<String,_>("name"),"kind":row.get::<Option<String>,_>("kind"),"models":models,"createdAt":row.get::<String,_>("createdAt"),"updatedAt":row.get::<String,_>("updatedAt")}),
    ))
}

async fn api_create_combo(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<impl IntoResponse, ApiError> {
    let name = b.get("name").and_then(Value::as_str).unwrap_or_default();
    if name.is_empty() {
        return Err(ApiError::bad_request("Name is required"));
    }
    if !valid_combo_name(name) {
        return Err(ApiError::bad_request(
            "Name can only contain letters, numbers, -, _ and .",
        ));
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM combos WHERE name=?")
        .bind(name)
        .fetch_one(&s.db)
        .await?;
    if exists != 0 {
        return Err(ApiError::bad_request("Combo name already exists"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    let models = b
        .get("models")
        .cloned()
        .filter(Value::is_array)
        .unwrap_or(json!([]));
    let kind = b.get("kind").and_then(Value::as_str);
    sqlx::query("INSERT INTO combos(id,name,kind,models,createdAt,updatedAt) VALUES(?,?,?,?,?,?)")
        .bind(&id)
        .bind(name)
        .bind(kind)
        .bind(models.to_string())
        .bind(&now)
        .bind(&now)
        .execute(&s.db)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"id":id,"name":name,"kind":kind,"models":models,"createdAt":now,"updatedAt":now}),
        ),
    ))
}

async fn api_update_combo(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let old = sqlx::query("SELECT id,name,kind,models,createdAt,updatedAt FROM combos WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.db)
        .await?
        .ok_or_else(|| ApiError::not_found("Combo not found"))?;
    use sqlx::Row;
    let name = b
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| old.get::<String, _>("name"));
    if !valid_combo_name(&name) {
        return Err(ApiError::bad_request(
            "Name can only contain letters, numbers, -, _ and .",
        ));
    }
    let clash: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM combos WHERE name=? AND id<>?")
        .bind(&name)
        .bind(&id)
        .fetch_one(&s.db)
        .await?;
    if clash != 0 {
        return Err(ApiError::bad_request("Combo name already exists"));
    }
    let kind = b.get("kind").cloned().unwrap_or_else(|| {
        old.get::<Option<String>, _>("kind")
            .map(Value::String)
            .unwrap_or(Value::Null)
    });
    let models = b.get("models").cloned().unwrap_or_else(|| {
        serde_json::from_str(old.get::<String, _>("models").as_str()).unwrap_or(json!([]))
    });
    let now = timestamp();
    sqlx::query("UPDATE combos SET name=?,kind=?,models=?,updatedAt=? WHERE id=?")
        .bind(&name)
        .bind(kind.as_str())
        .bind(models.to_string())
        .bind(&now)
        .bind(&id)
        .execute(&s.db)
        .await?;
    Ok(Json(
        json!({"id":id,"name":name,"kind":kind,"models":models,"createdAt":old.get::<String,_>("createdAt"),"updatedAt":now}),
    ))
}

async fn api_delete_combo(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let result = sqlx::query("DELETE FROM combos WHERE id=?")
        .bind(id)
        .execute(&s.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Combo not found"));
    }
    Ok(Json(json!({"success":true})))
}

async fn model_aliases(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({"aliases":kv_map(&s.db,"modelAliases").await?})))
}
async fn set_model_alias(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let model = b
        .get("model")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::bad_request("Model and alias required"))?;
    let alias = b
        .get("alias")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::bad_request("Model and alias required"))?;
    kv_set(&s.db, "modelAliases", alias, &json!(model)).await?;
    Ok(Json(json!({"success":true,"model":model,"alias":alias})))
}
async fn delete_model_alias(
    State(s): State<AppState>,
    OriginalUri(u): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let alias = u
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("alias="))
                .map(|x| x.replace('+', " "))
        })
        .unwrap_or_default();
    if alias.is_empty() {
        return Err(ApiError::bad_request("Alias required"));
    }
    sqlx::query("DELETE FROM kv WHERE scope='modelAliases' AND key=?")
        .bind(alias)
        .execute(&s.db)
        .await?;
    Ok(Json(json!({"success":true})))
}

async fn custom_models(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let map = kv_map(&s.db, "customModels").await?;
    Ok(Json(
        json!({"models":map.values().cloned().collect::<Vec<_>>()}),
    ))
}
async fn add_custom_model(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let provider = b
        .get("providerAlias")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::bad_request("providerAlias and id required"))?;
    let id = b
        .get("id")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::bad_request("providerAlias and id required"))?;
    let kind = b.get("type").and_then(Value::as_str).unwrap_or("llm");
    let key = format!("{provider}|{id}|{kind}");
    let previous = sqlx::query_scalar::<_, String>(
        "SELECT value FROM kv WHERE scope='customModels' AND key=?",
    )
    .bind(&key)
    .fetch_optional(&s.db)
    .await?;
    let added = previous.is_none();
    let mut value = previous
        .and_then(|v| serde_json::from_str::<Value>(&v).ok())
        .filter(Value::is_object)
        .unwrap_or(json!({"providerAlias":provider,"id":id,"type":kind,"name":id}));
    for field in ["name", "caps", "transport"] {
        if let Some(v) = b.get(field) {
            value[field] = v.clone();
        }
    }
    kv_set(&s.db, "customModels", &key, &value).await?;
    Ok(Json(json!({"success":true,"added":added})))
}
async fn delete_custom_model(
    State(s): State<AppState>,
    OriginalUri(u): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let params = query_pairs(u.query().unwrap_or_default());
    let provider = params.get("providerAlias").cloned().unwrap_or_default();
    let id = params.get("id").cloned().unwrap_or_default();
    if provider.is_empty() || id.is_empty() {
        return Err(ApiError::bad_request("providerAlias and id required"));
    }
    let kind = params.get("type").map(String::as_str).unwrap_or("llm");
    sqlx::query("DELETE FROM kv WHERE scope='customModels' AND key=?")
        .bind(format!("{provider}|{id}|{kind}"))
        .execute(&s.db)
        .await?;
    Ok(Json(json!({"success":true})))
}

async fn disabled_models(
    State(s): State<AppState>,
    OriginalUri(u): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let all = kv_map(&s.db, "disabledModels").await?;
    let q = query_pairs(u.query().unwrap_or_default());
    if let Some(provider) = q.get("providerAlias") {
        Ok(Json(
            json!({"ids":all.get(provider).cloned().unwrap_or(json!([]))}),
        ))
    } else {
        Ok(Json(json!({"disabled":all})))
    }
}
async fn disable_models(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let provider = b
        .get("providerAlias")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("providerAlias and ids[] required"))?;
    let ids = b
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request("providerAlias and ids[] required"))?;
    let mut all = sqlx::query_scalar::<_, String>(
        "SELECT value FROM kv WHERE scope='disabledModels' AND key=?",
    )
    .bind(provider)
    .fetch_optional(&s.db)
    .await?
    .and_then(|v| serde_json::from_str::<Value>(&v).ok())
    .and_then(|v| v.as_array().cloned())
    .unwrap_or_default();
    for id in ids {
        if !all.contains(id) {
            all.push(id.clone());
        }
    }
    kv_set(&s.db, "disabledModels", provider, &Value::Array(all)).await?;
    Ok(Json(json!({"success":true})))
}
async fn enable_models(
    State(s): State<AppState>,
    OriginalUri(u): OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let q = query_pairs(u.query().unwrap_or_default());
    let provider = q.get("providerAlias").cloned().unwrap_or_default();
    if provider.is_empty() {
        return Err(ApiError::bad_request("providerAlias required"));
    }
    if let Some(id) = q.get("id") {
        let mut ids = sqlx::query_scalar::<_, String>(
            "SELECT value FROM kv WHERE scope='disabledModels' AND key=?",
        )
        .bind(&provider)
        .fetch_optional(&s.db)
        .await?
        .and_then(|v| serde_json::from_str::<Value>(&v).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
        ids.retain(|v| v.as_str() != Some(id));
        if ids.is_empty() {
            sqlx::query("DELETE FROM kv WHERE scope='disabledModels' AND key=?")
                .bind(provider)
                .execute(&s.db)
                .await?;
        } else {
            kv_set(&s.db, "disabledModels", &provider, &Value::Array(ids)).await?;
        }
    } else {
        sqlx::query("DELETE FROM kv WHERE scope='disabledModels' AND key=?")
            .bind(provider)
            .execute(&s.db)
            .await?;
    }
    Ok(Json(json!({"success":true})))
}

async fn api_list_keys(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({"keys":read_keys(&s.db).await?})))
}

async fn api_get_settings(State(s): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let mut settings = read_settings(&s.db).await?;
    let obj = settings
        .as_object_mut()
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Invalid settings data"))?;
    let has_password = obj
        .get("password")
        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""));
    let oidc_secret = obj
        .remove("oidcClientSecret")
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    obj.remove("password");
    obj.remove("mitmSudoEncrypted");
    let oidc = obj
        .get("oidcIssuerUrl")
        .is_some_and(|v| !v.as_str().unwrap_or_default().is_empty())
        && obj
            .get("oidcClientId")
            .is_some_and(|v| !v.as_str().unwrap_or_default().is_empty())
        && !oidc_secret.is_empty();
    obj.insert("oidcConfigured".into(), json!(oidc));
    obj.insert("hasPassword".into(), json!(has_password));
    obj.insert(
        "enableRequestLogs".into(),
        json!(std::env::var("ENABLE_REQUEST_LOGS").as_deref() == Ok("true")),
    );
    obj.insert(
        "enableTranslator".into(),
        json!(std::env::var("ENABLE_TRANSLATOR").as_deref() == Ok("true")),
    );
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(settings)))
}

async fn api_patch_settings(
    State(s): State<AppState>,
    Json(mut patch): Json<Value>,
) -> Result<impl IntoResponse, ApiError> {
    let object = patch
        .as_object_mut()
        .ok_or_else(|| ApiError::bad_request("Settings must be a JSON object"))?;
    for protected in ["password", "mitmSudoEncrypted"] {
        object.remove(protected);
    }
    object.retain(|key, _| !key.to_ascii_lowercase().contains("headroom"));
    let current = read_settings(&s.db).await?;
    if let Some(new_password) = object
        .remove("newPassword")
        .and_then(|v| v.as_str().map(str::to_owned))
    {
        let old = current
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let supplied = object
            .remove("currentPassword")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        if !old.is_empty()
            && (supplied.is_empty() || !bcrypt::verify(&supplied, old).unwrap_or(false))
        {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                if supplied.is_empty() {
                    "Current password required"
                } else {
                    "Invalid current password"
                },
            ));
        }
        if old.is_empty() && !supplied.is_empty() && supplied != "123456" {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "Invalid current password",
            ));
        }
        let hashed = bcrypt::hash(new_password, bcrypt::DEFAULT_COST).map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Password hashing failed")
        })?;
        object.insert("password".into(), json!(hashed));
    } else {
        object.remove("currentPassword");
    }
    if object
        .get("oidcClientSecret")
        .is_some_and(|v| v.as_str().unwrap_or_default().trim().is_empty())
    {
        object.remove("oidcClientSecret");
    }
    let mut merged = current.as_object().cloned().unwrap_or_default();
    merged.extend(object.clone());
    let raw = Value::Object(merged);
    sqlx::query("INSERT INTO settings(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data").bind(raw.to_string()).execute(&s.db).await?;
    api_get_settings(State(s)).await
}

async fn read_settings(db: &SqlitePool) -> Result<Value, sqlx::Error> {
    let raw: Option<String> = sqlx::query_scalar("SELECT data FROM settings WHERE id=1")
        .fetch_optional(db)
        .await?;
    let mut settings = json!({"cloudEnabled":false,"tunnelEnabled":false,"tunnelUrl":"","tunnelProvider":"cloudflare","tailscaleEnabled":false,"tailscaleUrl":"","stickyRoundRobinLimit":3,"providerStrategies":{},"quotaVisibility":{},"comboStrategy":"fallback","comboStickyRoundRobinLimit":1,"comboStrategies":{},"capacityAdapter":{"vision":{"enabled":true,"roundRobin":false,"models":[]},"pdf":{"enabled":false,"roundRobin":false,"models":[]},"audioInput":{"enabled":true,"roundRobin":false,"models":[]},"videoInput":{"enabled":false,"roundRobin":false,"models":[]}},"requireLogin":true,"requireApiKey":true,"tunnelDashboardAccess":true,"authMode":"password","ssoType":"oidc","oidcIssuerUrl":"","oidcClientId":"","oidcClientSecret":"","oidcScopes":"openid profile email","oidcLoginLabel":"Sign in with OIDC","samlEntryPoint":"","samlIssuer":"urn:9router:sp","samlCert":"","samlLoginLabel":"Sign in with SAML SSO","samlAttributeEmail":"email","samlAttributeName":"name","enableObservability":false,"observabilityMaxRecords":1000,"observabilityBatchSize":20,"observabilityFlushIntervalMs":5000,"observabilityMaxJsonSize":5,"outboundProxyEnabled":false,"outboundProxyUrl":"","outboundNoProxy":"","mitmRouterBaseUrl":"http://localhost:20128","dnsToolEnabled":{},"rtkEnabled":true,"cavemanEnabled":false,"cavemanLevel":"full","ponytailEnabled":false,"ponytailLevel":"full","pxpipeEnabled":false,"pxpipeAutoInstall":true,"pxpipeMinChars":25000,"pxpipeTimeoutMs":15000,"providerOverrides":{}});
    if let Some(raw) = raw
        .and_then(|v| serde_json::from_str::<Value>(&v).ok())
        .and_then(|v| v.as_object().cloned())
    {
        for (k, v) in raw {
            if !k.to_lowercase().contains("headroom") {
                settings[&k] = v;
            }
        }
    }
    Ok(settings)
}

async fn api_export_database(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let supplied = headers
        .get("x-9r-password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let settings = match read_settings(&s.db).await {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"Failed to export database"})),
            )
                .into_response();
        }
    };
    if !verify_dashboard_password(&settings, supplied) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Invalid password"})),
        )
            .into_response();
    }
    let raw_settings: Option<String> =
        match sqlx::query_scalar("SELECT data FROM settings WHERE id=1")
            .fetch_optional(&s.db)
            .await
        {
            Ok(value) => value,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"Failed to export database"})),
                )
                    .into_response();
            }
        };
    let raw_settings = raw_settings
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(json!({}));
    match export_database(&s.db, raw_settings).await {
        Ok(payload) => Json(payload).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Failed to export database"})),
        )
            .into_response(),
    }
}

async fn api_import_database(
    State(s): State<AppState>,
    Json(mut payload): Json<Value>,
) -> Response {
    let supplied = payload
        .as_object_mut()
        .and_then(|o| o.remove("password"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let settings = match read_settings(&s.db).await {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"Failed to read settings"})),
            )
                .into_response();
        }
    };
    if !verify_dashboard_password(&settings, &supplied) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Invalid password"})),
        )
            .into_response();
    }
    match import_database(&s.db, payload).await {
        Ok(()) => Json(json!({"success":true})).into_response(),
        Err(message) => (StatusCode::BAD_REQUEST, Json(json!({"error":message}))).into_response(),
    }
}

fn verify_dashboard_password(settings: &Value, supplied: &str) -> bool {
    if let Some(hash) = settings
        .get("password")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        bcrypt::verify(supplied, hash).unwrap_or(false)
    } else {
        supplied == std::env::var("INITIAL_PASSWORD").unwrap_or_else(|_| "123456".into())
    }
}

async fn export_database(db: &SqlitePool, settings: Value) -> Result<Value, sqlx::Error> {
    use sqlx::Row;
    let mut connections = Vec::new();
    for row in sqlx::query("SELECT id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt FROM providerConnections ORDER BY createdAt")
        .fetch_all(db).await? {
        let mut item = serde_json::from_str::<Value>(&row.get::<String,_>("data")).unwrap_or(json!({}));
        if !item.is_object() { item = json!({}); }
        let object = item.as_object_mut().expect("object initialized");
        for field in ["id","provider","authType","name","email","priority","isActive","createdAt","updatedAt"] { object.remove(field); }
        object.insert("id".into(), json!(row.get::<String,_>("id")));
        object.insert("provider".into(), json!(row.get::<String,_>("provider")));
        object.insert("authType".into(), json!(row.get::<String,_>("authType")));
        object.insert("name".into(), json!(row.get::<Option<String>,_>("name")));
        object.insert("email".into(), json!(row.get::<Option<String>,_>("email")));
        object.insert("priority".into(), json!(row.get::<Option<i64>,_>("priority")));
        object.insert("isActive".into(), json!(row.get::<i64,_>("isActive") == 1));
        object.insert("createdAt".into(), json!(row.get::<String,_>("createdAt")));
        object.insert("updatedAt".into(), json!(row.get::<String,_>("updatedAt")));
        connections.push(item);
    }
    let mut nodes = Vec::new();
    for row in sqlx::query(
        "SELECT id,type,name,data,createdAt,updatedAt FROM providerNodes ORDER BY createdAt",
    )
    .fetch_all(db)
    .await?
    {
        let mut item =
            serde_json::from_str::<Value>(&row.get::<String, _>("data")).unwrap_or(json!({}));
        if !item.is_object() {
            item = json!({});
        }
        let object = item.as_object_mut().expect("object initialized");
        object.insert("id".into(), json!(row.get::<String, _>("id")));
        object.insert("type".into(), json!(row.get::<Option<String>, _>("type")));
        object.insert("name".into(), json!(row.get::<Option<String>, _>("name")));
        object.insert("createdAt".into(), json!(row.get::<String, _>("createdAt")));
        object.insert("updatedAt".into(), json!(row.get::<String, _>("updatedAt")));
        nodes.push(item);
    }
    let mut pools = Vec::new();
    for row in sqlx::query(
        "SELECT id,isActive,testStatus,data,createdAt,updatedAt FROM proxyPools ORDER BY createdAt",
    )
    .fetch_all(db)
    .await?
    {
        let mut item =
            serde_json::from_str::<Value>(&row.get::<String, _>("data")).unwrap_or(json!({}));
        if !item.is_object() {
            item = json!({});
        }
        let object = item.as_object_mut().expect("object initialized");
        object.insert("id".into(), json!(row.get::<String, _>("id")));
        object.insert("isActive".into(), json!(row.get::<i64, _>("isActive") == 1));
        object.insert(
            "testStatus".into(),
            json!(row.get::<Option<String>, _>("testStatus")),
        );
        object.insert("createdAt".into(), json!(row.get::<String, _>("createdAt")));
        object.insert("updatedAt".into(), json!(row.get::<String, _>("updatedAt")));
        pools.push(item);
    }
    let mut combos = Vec::new();
    for row in
        sqlx::query("SELECT id,name,kind,models,createdAt,updatedAt FROM combos ORDER BY createdAt")
            .fetch_all(db)
            .await?
    {
        combos.push(json!({"id":row.get::<String,_>("id"),"name":row.get::<String,_>("name"),"kind":row.get::<Option<String>,_>("kind"),"models":serde_json::from_str::<Value>(&row.get::<String,_>("models")).unwrap_or(json!([])),"createdAt":row.get::<String,_>("createdAt"),"updatedAt":row.get::<String,_>("updatedAt")}));
    }
    let mut custom_models = Vec::new();
    for value in kv_map(db, "customModels").await?.into_values() {
        custom_models.push(value);
    }
    Ok(
        json!({"settings":settings,"providerConnections":connections,"providerNodes":nodes,"proxyPools":pools,"apiKeys":read_keys(db).await?,"combos":combos,"modelAliases":kv_map(db,"modelAliases").await?,"customModels":custom_models,"mitmAlias":kv_map(db,"mitmAlias").await?,"pricing":kv_map(db,"pricing").await?}),
    )
}

async fn import_database(db: &SqlitePool, payload: Value) -> Result<(), String> {
    let root = payload
        .as_object()
        .ok_or("Database payload must be an object")?;
    for key in [
        "providerConnections",
        "providerNodes",
        "proxyPools",
        "apiKeys",
        "combos",
        "customModels",
    ] {
        if root.get(key).is_some_and(|v| !v.is_array()) {
            return Err(format!("{key} must be an array"));
        }
    }
    for key in ["settings", "modelAliases", "mitmAlias", "pricing"] {
        if root.get(key).is_some_and(|v| !v.is_object()) {
            return Err(format!("{key} must be an object"));
        }
    }
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    for table in [
        "providerConnections",
        "providerNodes",
        "proxyPools",
        "apiKeys",
        "combos",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    }
    sqlx::query("DELETE FROM settings")
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        "DELETE FROM kv WHERE scope IN ('modelAliases','customModels','mitmAlias','pricing')",
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let now = timestamp();
    if let Some(value) = root.get("settings") {
        sqlx::query("INSERT INTO settings(id,data) VALUES(1,?)")
            .bind(value.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    }
    for item in root
        .get("providerConnections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = required_string(item, "id")?;
        let provider = required_string(item, "provider")?;
        let auth = item
            .get("authType")
            .and_then(Value::as_str)
            .unwrap_or("oauth");
        let name = item.get("name").and_then(Value::as_str);
        let email = item.get("email").and_then(Value::as_str);
        let priority = item.get("priority").and_then(Value::as_i64);
        let active = item
            .get("isActive")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let created = item
            .get("createdAt")
            .and_then(Value::as_str)
            .unwrap_or(&now);
        let updated = item
            .get("updatedAt")
            .and_then(Value::as_str)
            .unwrap_or(&now);
        let data = without_fields(
            item,
            &[
                "id",
                "provider",
                "authType",
                "name",
                "email",
                "priority",
                "isActive",
                "createdAt",
                "updatedAt",
            ],
        );
        sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(id).bind(provider).bind(auth).bind(name).bind(email).bind(priority).bind(if active{1}else{0}).bind(data.to_string()).bind(created).bind(updated).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    }
    for item in root
        .get("providerNodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = required_string(item, "id")?;
        let typ = item.get("type").and_then(Value::as_str);
        let name = item.get("name").and_then(Value::as_str);
        let created = item
            .get("createdAt")
            .and_then(Value::as_str)
            .unwrap_or(&now);
        let updated = item
            .get("updatedAt")
            .and_then(Value::as_str)
            .unwrap_or(&now);
        let data = without_fields(item, &["id", "type", "name", "createdAt", "updatedAt"]);
        sqlx::query(
            "INSERT INTO providerNodes(id,type,name,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?)",
        )
        .bind(id)
        .bind(typ)
        .bind(name)
        .bind(data.to_string())
        .bind(created)
        .bind(updated)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    for item in root
        .get("proxyPools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = required_string(item, "id")?;
        let active = item
            .get("isActive")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let status = item
            .get("testStatus")
            .and_then(Value::as_str)
            .or(Some("unknown"));
        let created = item
            .get("createdAt")
            .and_then(Value::as_str)
            .unwrap_or(&now);
        let updated = item
            .get("updatedAt")
            .and_then(Value::as_str)
            .unwrap_or(&now);
        let data = without_fields(
            item,
            &["id", "isActive", "testStatus", "createdAt", "updatedAt"],
        );
        sqlx::query("INSERT INTO proxyPools(id,isActive,testStatus,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?)").bind(id).bind(if active{1}else{0}).bind(status).bind(data.to_string()).bind(created).bind(updated).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    }
    for item in root
        .get("apiKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = required_string(item, "id")?;
        let key = required_string(item, "key")?;
        let (restricted, allow) = if let Some(access) = item.get("access") {
            let restricted = access
                .get("restricted")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("apiKeys {id}: access.restricted must be a boolean"))?;
            let allow = access
                .get("allow")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("apiKeys {id}: access.allow must be an array"))?
                .clone();
            if allow.len() > 200
                || allow
                    .iter()
                    .any(|v| v.as_str().is_none_or(|s| s.trim().len() > 200))
            {
                return Err(format!("apiKeys {id}: invalid access allow list"));
            }
            (restricted, Value::Array(allow))
        } else {
            (false, json!([]))
        };
        sqlx::query("INSERT INTO apiKeys(id,key,name,machineId,isActive,createdAt,accessRestricted,accessAllow) VALUES(?,?,?,?,?,?,?,?)").bind(id).bind(key).bind(item.get("name").and_then(Value::as_str)).bind(item.get("machineId").and_then(Value::as_str)).bind(if item.get("isActive").and_then(Value::as_bool).unwrap_or(true){1}else{0}).bind(item.get("createdAt").and_then(Value::as_str).unwrap_or(&now)).bind(if restricted{1}else{0}).bind(allow.to_string()).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    }
    for item in root
        .get("combos")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = required_string(item, "id")?;
        let name = required_string(item, "name")?;
        let models = item
            .get("models")
            .filter(|v| v.is_array())
            .cloned()
            .unwrap_or(json!([]));
        sqlx::query(
            "INSERT INTO combos(id,name,kind,models,createdAt,updatedAt) VALUES(?,?,?,?,?,?)",
        )
        .bind(id)
        .bind(name)
        .bind(item.get("kind").and_then(Value::as_str))
        .bind(models.to_string())
        .bind(
            item.get("createdAt")
                .and_then(Value::as_str)
                .unwrap_or(&now),
        )
        .bind(
            item.get("updatedAt")
                .and_then(Value::as_str)
                .unwrap_or(&now),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    for (scope, key_name) in [
        ("modelAliases", "modelAliases"),
        ("mitmAlias", "mitmAlias"),
        ("pricing", "pricing"),
    ] {
        if let Some(map) = root.get(key_name).and_then(Value::as_object) {
            for (key, value) in map {
                sqlx::query("INSERT INTO kv(scope,key,value) VALUES(?,?,?)")
                    .bind(scope)
                    .bind(key)
                    .bind(value.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    if let Some(items) = root.get("customModels").and_then(Value::as_array) {
        for item in items {
            let provider = item
                .get("providerAlias")
                .or_else(|| item.get("provider"))
                .and_then(Value::as_str)
                .ok_or("customModels item requires providerAlias")?;
            let id = required_string(item, "id")?;
            let kind = item.get("type").and_then(Value::as_str).unwrap_or("llm");
            let key = format!("{provider}|{id}|{kind}");
            sqlx::query("INSERT INTO kv(scope,key,value) VALUES('customModels',?,?)")
                .bind(key)
                .bind(item.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Missing {field}"))
}

fn without_fields(value: &Value, fields: &[&str]) -> Value {
    let mut result = value.clone();
    if let Some(object) = result.as_object_mut() {
        for field in fields {
            object.remove(*field);
        }
    }
    result
}
async fn api_get_key(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = read_keys(&s.db)
        .await?
        .into_iter()
        .find(|k| k["id"] == id)
        .ok_or_else(|| ApiError::not_found("Key not found"))?;
    Ok(Json(json!({"key":key})))
}
async fn api_create_key(
    State(s): State<AppState>,
    Json(b): Json<Value>,
) -> Result<impl IntoResponse, ApiError> {
    let name = b
        .get("name")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::bad_request("Name is required"))?;
    let data_dir = std::env::var("DATA_DIR")
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| format!("{home}/.9router"))
        })
        .unwrap_or_else(|| "./data".into());
    let machine_id_path = format!("{data_dir}/machine-id");
    let raw = match tokio::fs::read_to_string(&machine_id_path).await {
        Ok(existing) if !existing.trim().is_empty() => existing,
        _ => {
            let id = uuid::Uuid::new_v4().to_string();
            let _ = tokio::fs::create_dir_all(&data_dir).await;
            let _ = tokio::fs::write(&machine_id_path, &id).await;
            id
        }
    };
    let salt = std::env::var("MACHINE_ID_SALT").unwrap_or_else(|_| "endpoint-proxy-salt".into());
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(format!("{}{}", raw.trim(), salt));
    let machine_id = hex::encode(hasher.finalize())[..16].to_string();
    let key_id = uuid::Uuid::new_v4().simple().to_string()[..6].to_string();
    let secret =
        std::env::var("API_KEY_SECRET").unwrap_or_else(|_| "endpoint-proxy-api-key-secret".into());
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Invalid API_KEY_SECRET"))?;
    mac.update(format!("{machine_id}{key_id}").as_bytes());
    let crc = hex::encode(mac.finalize().into_bytes())[..8].to_string();
    let token = format!("sk-{machine_id}-{key_id}-{crc}");
    let id = uuid::Uuid::new_v4().to_string();
    let now = timestamp();
    sqlx::query("INSERT INTO apiKeys(id,key,name,machineId,isActive,createdAt,accessRestricted,accessAllow) VALUES(?,?,?,?,1,?,0,'[]')").bind(&id).bind(&token).bind(name).bind(&machine_id).bind(now).execute(&s.db).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"key":token,"name":name,"id":id,"machineId":machine_id})),
    ))
}
async fn api_update_key(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let mut key = api_get_key(State(s.clone()), Path(id.clone())).await?.0["key"].clone();
    let active = b.get("isActive").and_then(Value::as_bool);
    if let Some(a) = active {
        sqlx::query("UPDATE apiKeys SET isActive=? WHERE id=?")
            .bind(if a { 1 } else { 0 })
            .bind(&id)
            .execute(&s.db)
            .await?;
        key["isActive"] = json!(a);
    }
    if let Some(access) = b.get("access") {
        let restricted = access
            .get("restricted")
            .and_then(Value::as_bool)
            .ok_or_else(|| ApiError::bad_request("access.restricted must be a boolean"))?;
        let allow = access
            .get("allow")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if allow.len() > 200
            || allow
                .iter()
                .any(|v| v.as_str().is_none_or(|x| x.trim().len() > 200))
        {
            return Err(ApiError::bad_request("Invalid access allow list"));
        }
        sqlx::query("UPDATE apiKeys SET accessRestricted=?,accessAllow=? WHERE id=?")
            .bind(if restricted { 1 } else { 0 })
            .bind(Value::Array(allow.clone()).to_string())
            .bind(&id)
            .execute(&s.db)
            .await?;
        key["access"] = json!({"restricted":restricted,"allow":allow});
    }
    Ok(Json(json!({"key":key})))
}
async fn api_delete_key(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let r = sqlx::query("DELETE FROM apiKeys WHERE id=?")
        .bind(id)
        .execute(&s.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("Key not found"));
    }
    Ok(Json(json!({"message":"Key deleted successfully"})))
}

async fn read_keys(db: &SqlitePool) -> Result<Vec<Value>, sqlx::Error> {
    use sqlx::Row;
    let rows=sqlx::query("SELECT id,key,name,machineId,isActive,createdAt,accessRestricted,accessAllow FROM apiKeys ORDER BY createdAt ASC").fetch_all(db).await?;
    Ok(rows.into_iter().map(|r|{let allow=r.get::<Option<String>,_>("accessAllow").and_then(|x|serde_json::from_str::<Value>(&x).ok()).unwrap_or(json!([]));json!({"id":r.get::<String,_>("id"),"key":r.get::<String,_>("key"),"name":r.get::<Option<String>,_>("name"),"machineId":r.get::<Option<String>,_>("machineId"),"isActive":r.get::<i64,_>("isActive")==1,"createdAt":r.get::<String,_>("createdAt"),"access":{"restricted":r.get::<i64,_>("accessRestricted")==1,"allow":allow}})}).collect())
}

async fn kv_map(
    db: &SqlitePool,
    scope: &str,
) -> Result<std::collections::HashMap<String, Value>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT key,value FROM kv WHERE scope=?")
        .bind(scope)
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            serde_json::from_str::<Value>(r.get::<String, _>("value").as_str())
                .ok()
                .map(|v| (r.get("key"), v))
        })
        .collect())
}
async fn kv_set(db: &SqlitePool, scope: &str, key: &str, value: &Value) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO kv(scope,key,value) VALUES(?,?,?) ON CONFLICT(scope,key) DO UPDATE SET value=excluded.value").bind(scope).bind(key).bind(value.to_string()).execute(db).await?;
    Ok(())
}
fn query_pairs(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.into(), v.replace('+', " ")))
        .collect()
}
fn valid_combo_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}
fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

async fn list_models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize(&state, &headers).await?;
    authorize_stored_key(&state, &headers).await?;
    let restricted_allow = restricted_key_allow(&state, &headers).await?;
    let mut data = Vec::new();
    for provider in store::list_providers(&state.db)
        .await?
        .into_iter()
        .filter(|p| p.enabled != 0)
    {
        for model in store::models(&provider) {
            let model_id = format!("{}/{}", provider.id, model);
            if restricted_allow.as_ref().is_none_or(|allow| {
                allow
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(&model_id))
            }) {
                data.push(json!({"id":model_id,"object":"model","owned_by":provider.id}));
            }
        }
    }
    for combo in store::list_combos(&state.db)
        .await?
        .into_iter()
        .filter(|c| c.enabled != 0)
    {
        if restricted_allow.as_ref().is_none_or(|allow| {
            allow
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(&combo.name))
        }) {
            data.push(json!({"id":combo.name,"object":"model","owned_by":"9router"}));
        }
    }
    if headers.contains_key("anthropic-version") {
        let data: Vec<Value> = data.into_iter().map(|model| {
            let id = model.get("id").and_then(Value::as_str).unwrap_or_default();
            json!({"type":"model","id":id,"display_name":id,"created_at":"2025-01-01T00:00:00Z"})
        }).collect();
        Ok(Json(json!({"data":data,"has_more":false})))
    } else {
        Ok(Json(json!({"object":"list","data":data})))
    }
}

async fn proxy(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    if method == Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("*"),
        );
        return Ok(response);
    }
    authorize(&state, &headers).await?;
    authorize_stored_key(&state, &headers).await?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let content_type_is_json = content_type.contains("json");
    let content_type_is_multipart = content_type.contains("multipart/form-data");
    let has_model_header = headers.contains_key("x-9router-model");
    let inspect_body = content_type_is_json || content_type_is_multipart || !has_model_header;
    let mut streaming_body = Some(body);
    let body = if inspect_body {
        Some(
            to_bytes(
                streaming_body.take().expect("request body is present"),
                MAX_PROXY_BODY_BYTES,
            )
            .await
            .map_err(|_| ApiError::bad_request("Request body exceeds the 50 MiB limit"))?,
        )
    } else {
        None
    };
    let body_is_json = content_type_is_json
        || body
            .as_ref()
            .is_some_and(|body| body.first().is_some_and(|b| *b == b'{' || *b == b'['));
    let request_json: Value = if body_is_json && body.as_ref().is_some_and(|body| !body.is_empty())
    {
        serde_json::from_slice(body.as_ref().expect("JSON body is present"))
            .map_err(|_| ApiError::bad_request("Request body must be valid JSON"))?
    } else {
        json!({})
    };
    let multipart_range = if content_type_is_multipart {
        body.as_ref()
            .and_then(|body| multipart_field_range(content_type, body, "model"))
    } else {
        None
    };
    let requested_model = request_json
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            multipart_range.as_ref().and_then(|range| {
                body.as_ref()
                    .and_then(|body| String::from_utf8(body[range.clone()].to_vec()).ok())
            })
        })
        .or_else(|| {
            headers
                .get("x-9router-model")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();
    if requested_model.is_empty() {
        return Err(ApiError::bad_request(
            "Missing model (set the model field or x-9router-model header)",
        ));
    }
    enforce_key_access(&state, &headers, &requested_model).await?;
    let payload = request_json;
    let targets = resolve_targets(&state.db, &requested_model).await?;
    if targets.is_empty() {
        return Err(ApiError::not_found(
            "Model or combo has no configured targets",
        ));
    }

    let started = Instant::now();
    let request_format = if path.starts_with("messages") {
        "anthropic"
    } else {
        "openai"
    };
    let mut candidates = Vec::new();
    // Route across every active account in priority order. The same provider
    // may have several OAuth/API-key accounts; each is attempted separately.
    let providers = store::list_routing_accounts(&state.db).await?;
    let pinned_account = headers.get("x-connection-id").and_then(|v| v.to_str().ok());
    for target in &targets {
        let (provider_id, model) = target
            .split_once('/')
            .ok_or_else(|| ApiError::bad_request("Targets must use provider/model format"))?;
        for provider in providers
            .iter()
            .filter(|provider| provider.id == provider_id)
            .filter(|provider| {
                pinned_account.is_none_or(|id| provider.connection_id.as_deref() == Some(id))
            })
        {
            let available = store::models(provider);
            if !available.is_empty() && !available.iter().any(|item| item == model) {
                continue;
            }
            candidates.push((target.clone(), provider.clone(), model.to_string()));
        }
    }
    let mut last_error: Option<String> = None;
    let candidate_count = candidates.len();
    let opaque_stream_eligible = !matches!(path.as_str(), "messages" | "chat/completions");
    // The opaque fast path is safe only when the request has one target and
    // no protocol conversion can require the body to be inspected.
    let body = if body.is_none() && (candidate_count != 1 || !opaque_stream_eligible) {
        Some(
            to_bytes(
                streaming_body
                    .take()
                    .expect("streaming request body is present"),
                MAX_PROXY_BODY_BYTES,
            )
            .await
            .map_err(|_| ApiError::bad_request("Request body exceeds the 50 MiB limit"))?,
        )
    } else {
        body
    };
    for (index, (target, mut provider, model)) in candidates.into_iter().enumerate() {
        if let Err(error) = refresh_oauth_account(&state, &mut provider).await {
            last_error = Some(error);
            continue;
        }
        let mut outbound = payload.clone();
        if let Some(obj) = outbound.as_object_mut() {
            obj.insert("model".into(), Value::String(model.clone()));
        }
        let translating = (request_format == "anthropic") != (provider.api_format == "anthropic")
            && (path == "messages" || path == "chat/completions");
        if translating && outbound["stream"] == true {
            return Err(ApiError::bad_request(
                "Cross-protocol streaming conversion is not supported; set stream to false",
            ));
        }
        let mut upstream_path = path.trim_start_matches('/').to_string();
        if translating {
            outbound = translate_request(&outbound, request_format, &provider.api_format);
            upstream_path = if request_format == "anthropic" {
                "chat/completions".into()
            } else {
                "messages".into()
            };
        }
        let upstream_path = format!(
            "{}/{}",
            provider.api_path_prefix.trim_matches('/'),
            upstream_path
        );
        let upstream_url = endpoint_url(&provider.base_url, &upstream_path, uri.query())?;
        // JSON requests are serialized from the parsed payload below. For
        // opaque bodies, retain Axum's reference-counted Bytes buffer instead
        // of copying the whole upload once per candidate account.
        let outbound_body = if body_is_json {
            None
        } else if let Some(range) = &multipart_range {
            let mut rewritten = body
                .as_ref()
                .expect("multipart request body is buffered")
                .to_vec();
            rewritten.splice(range.clone(), model.bytes());
            Some(reqwest::Body::from(rewritten))
        } else if let Some(body) = &body {
            Some(reqwest::Body::from(body.clone()))
        } else {
            let stream = streaming_body
                .take()
                .expect("opaque request body is available")
                .into_data_stream()
                .scan((0usize, false), |(total, failed), chunk| {
                    let next = if *failed {
                        None
                    } else {
                        match chunk {
                            Ok(bytes) => {
                                *total = total.saturating_add(bytes.len());
                                if *total > MAX_PROXY_BODY_BYTES {
                                    *failed = true;
                                    Some(Err(std::io::Error::other(
                                        "Request body exceeds the 50 MiB limit",
                                    )))
                                } else {
                                    Some(Ok(bytes))
                                }
                            }
                            Err(error) => {
                                *failed = true;
                                Some(Err(std::io::Error::other(error)))
                            }
                        }
                    };
                    std::future::ready(next)
                });
            Some(reqwest::Body::wrap_stream(stream))
        };
        match send_upstream(
            &state,
            &provider,
            &headers,
            method.clone(),
            &upstream_url,
            outbound_body,
            body_is_json,
            &outbound,
        )
        .await
        {
            Ok(upstream) => {
                let status = upstream.status().as_u16();
                if is_retryable(status) && index + 1 < candidate_count {
                    last_error = Some(format!("Upstream returned HTTP {status}"));
                    let _ = upstream.bytes().await;
                    continue;
                }
                store::log_request(
                    &state.db,
                    &requested_model,
                    &target,
                    status,
                    started.elapsed().as_millis(),
                )
                .await;
                if translating && status < 400 {
                    let response_status = upstream.status();
                    let response_headers = upstream.headers().clone();
                    let response_bytes = upstream
                        .bytes()
                        .await
                        .map_err(|e| ApiError::upstream(e.to_string()))?;
                    let translated = translate_response(
                        &response_bytes,
                        request_format,
                        &provider.api_format,
                        &requested_model,
                    );
                    return Ok(translated_response(
                        response_status.as_u16(),
                        &response_headers,
                        translated,
                    ));
                }
                return Ok(upstream_response(upstream));
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }
    store::log_request(
        &state.db,
        &requested_model,
        "",
        502,
        started.elapsed().as_millis(),
    )
    .await;
    Err(ApiError::upstream(
        last_error.unwrap_or_else(|| "All configured targets failed".into()),
    ))
}

async fn proxy_root(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    proxy(
        State(state),
        OriginalUri(uri),
        Path(String::new()),
        method,
        headers,
        body,
    )
    .await
}

fn translate_request(input: &Value, from: &str, to: &str) -> Value {
    let Some(messages) = input.get("messages").and_then(Value::as_array) else {
        return input.clone();
    };
    if from == "openai" && to == "anthropic" {
        let mut system = Vec::new();
        let mut output = Vec::new();
        for message in messages {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user");
            if role == "system" || role == "developer" {
                if let Some(text) = message.get("content").and_then(Value::as_str) {
                    system.push(text.to_string());
                }
                continue;
            }
            let mut item = json!({"role": if role == "assistant" { "assistant" } else { "user" }, "content": message.get("content").cloned().unwrap_or(Value::String(String::new()))});
            if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                let blocks: Vec<Value> = calls.iter().map(|call| {
                    let function = &call["function"];
                    let input = function.get("arguments").and_then(Value::as_str).and_then(|s| serde_json::from_str(s).ok()).unwrap_or_else(|| json!({}));
                    json!({"type":"tool_use","id":call.get("id").cloned().unwrap_or(Value::Null),"name":function.get("name").cloned().unwrap_or(Value::Null),"input":input})
                }).collect();
                let mut content = item["content"].as_array().cloned().unwrap_or_else(|| {
                    item["content"]
                        .as_str()
                        .map(|s| vec![json!({"type":"text","text":s})])
                        .unwrap_or_default()
                });
                content.extend(blocks);
                item["content"] = Value::Array(content);
            }
            output.push(item);
        }
        let mut result = json!({"model":input.get("model"),"messages":output,"max_tokens":input.get("max_tokens").or_else(|| input.get("max_completion_tokens")).cloned().unwrap_or(json!(4096))});
        if !system.is_empty() {
            result["system"] = json!(system.join("\n\n"));
        }
        for key in ["temperature", "top_p", "stop"] {
            if let Some(value) = input.get(key) {
                result[if key == "stop" { "stop_sequences" } else { key }] = value.clone();
            }
        }
        if let Some(tools) = input.get("tools").and_then(Value::as_array) {
            result["tools"] = Value::Array(tools.iter().map(|tool| {
                let f = tool.get("function").unwrap_or(tool);
                json!({"name":f.get("name"),"description":f.get("description"),"input_schema":f.get("parameters").cloned().unwrap_or(json!({"type":"object","properties":{}}))})
            }).collect());
        }
        if let Some(choice) = input.get("tool_choice") {
            result["tool_choice"] = if choice == "auto" || choice == "none" {
                json!({"type":choice})
            } else if choice == "required" {
                json!({"type":"any"})
            } else {
                json!({"type":"tool","name":choice["function"]["name"]})
            };
        }
        result
    } else if from == "anthropic" && to == "openai" {
        let mut output = Vec::new();
        if let Some(system) = input.get("system") {
            output.push(json!({"role":"system","content":system}));
        }
        for message in messages {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user");
            let mut text_parts = Vec::new();
            let mut tool_calls = Vec::new();
            let mut tool_results = Vec::new();
            let content = message.get("content").cloned().unwrap_or(Value::Null);
            let blocks = content
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![json!({"type":"text","text":content})]);
            for block in blocks {
                match block.get("type").and_then(Value::as_str).unwrap_or("text") {
                    "text" => if let Some(text) = block.get("text").and_then(Value::as_str) { text_parts.push(text.to_string()); },
                    "tool_use" => tool_calls.push(json!({"id":block.get("id"),"type":"function","function":{"name":block.get("name"),"arguments":block.get("input").cloned().unwrap_or(json!({})).to_string()}})),
                    "tool_result" => tool_results.push(json!({"role":"tool","tool_call_id":block.get("tool_use_id"),"content":block.get("content")})),
                    _ => {}
                }
            }
            if !text_parts.is_empty() || !tool_calls.is_empty() {
                let mut item = json!({"role":role,"content":if text_parts.is_empty() { Value::Null } else { json!(text_parts.join("\n")) }});
                if !tool_calls.is_empty() {
                    item["tool_calls"] = Value::Array(tool_calls);
                }
                output.push(item);
            }
            output.extend(tool_results);
        }
        let mut result = json!({"model":input.get("model"),"messages":output});
        for (source, target) in [
            ("max_tokens", "max_tokens"),
            ("temperature", "temperature"),
            ("top_p", "top_p"),
            ("stop_sequences", "stop"),
        ] {
            if let Some(value) = input.get(source) {
                result[target] = value.clone();
            }
        }
        if let Some(tools) = input.get("tools").and_then(Value::as_array) {
            result["tools"] = Value::Array(tools.iter().map(|tool| json!({"type":"function","function":{"name":tool.get("name"),"description":tool.get("description"),"parameters":tool.get("input_schema")}})).collect());
        }
        result
    } else {
        input.clone()
    }
}

fn translate_response(
    body: &[u8],
    client_format: &str,
    upstream_format: &str,
    model: &str,
) -> Bytes {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Bytes::copy_from_slice(body),
    };
    let translated = if client_format == "openai" && upstream_format == "anthropic" {
        let content = value
            .get("content")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut text = String::new();
        let mut calls = Vec::new();
        for block in content {
            match block.get("type").and_then(Value::as_str).unwrap_or("") {
                "text" => text.push_str(block.get("text").and_then(Value::as_str).unwrap_or_default()),
                "tool_use" => calls.push(json!({"id":block.get("id"),"type":"function","function":{"name":block.get("name"),"arguments":block.get("input").cloned().unwrap_or(json!({})).to_string()}})),
                _ => {}
            }
        }
        let mut message = json!({"role":"assistant","content":if text.is_empty() { Value::Null } else { json!(text) }});
        if !calls.is_empty() {
            message["tool_calls"] = Value::Array(calls);
        }
        json!({"id":value.get("id"),"object":"chat.completion","created":chrono::Utc::now().timestamp(),"model":value.get("model").and_then(Value::as_str).unwrap_or(model),"choices":[{"index":0,"message":message,"finish_reason":if value.get("stop_reason").and_then(Value::as_str)==Some("tool_use") {"tool_calls"} else {"stop"}}],"usage":{"prompt_tokens":value["usage"]["input_tokens"],"completion_tokens":value["usage"]["output_tokens"],"total_tokens":value["usage"]["input_tokens"].as_i64().unwrap_or(0)+value["usage"]["output_tokens"].as_i64().unwrap_or(0)}})
    } else if client_format == "anthropic" && upstream_format == "openai" {
        let choice = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or(json!({}));
        let message = choice.get("message").cloned().unwrap_or(json!({}));
        let mut content = Vec::new();
        if let Some(text) = message
            .get("content")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            content.push(json!({"type":"text","text":text}));
        }
        if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                let input = call["function"]["arguments"]
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| json!({}));
                content.push(json!({"type":"tool_use","id":call.get("id"),"name":call["function"]["name"],"input":input}));
            }
        }
        let usage = value.get("usage").cloned().unwrap_or(json!({}));
        json!({"id":value.get("id"),"type":"message","role":"assistant","model":value.get("model").and_then(Value::as_str).unwrap_or(model),"content":content,"stop_reason":if message.get("tool_calls").is_some() {"tool_use"} else {"end_turn"},"stop_sequence":Value::Null,"usage":{"input_tokens":usage.get("prompt_tokens"),"output_tokens":usage.get("completion_tokens")}})
    } else {
        value
    };
    Bytes::from(serde_json::to_vec(&translated).unwrap_or_else(|_| body.to_vec()))
}

fn translated_response(
    status: u16,
    source_headers: &reqwest::header::HeaderMap,
    body: Bytes,
) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for name in ["retry-after", "x-request-id", "request-id"] {
        if let (Some(value), Ok(key)) = (
            source_headers.get(name),
            name.parse::<axum::http::HeaderName>(),
        ) {
            response.headers_mut().insert(key, value.clone());
        }
    }
    response
}

fn multipart_field_range(
    content_type: &str,
    body: &[u8],
    field: &str,
) -> Option<std::ops::Range<usize>> {
    let boundary = content_type.split(';').skip(1).find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name.trim().eq_ignore_ascii_case("boundary"))
            .then(|| value.trim().trim_matches('"').to_string())
    })?;
    if boundary.is_empty() {
        return None;
    }
    let marker = format!("--{boundary}").into_bytes();
    let mut cursor = 0;
    while let Some(offset) = body[cursor..]
        .windows(marker.len())
        .position(|window| window == marker)
    {
        let part_start = cursor + offset + marker.len();
        let header_end = body[part_start..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")?
            + part_start;
        let headers = std::str::from_utf8(&body[part_start..header_end]).ok()?;
        let named_field = format!("name=\"{field}\"");
        let is_target = headers
            .lines()
            .any(|line| line.to_ascii_lowercase().contains(&named_field));
        let value_start = header_end + 4;
        let next = body[value_start..]
            .windows(2)
            .position(|window| window == b"\r\n")?
            + value_start;
        if is_target {
            return Some(value_start..next);
        }
        cursor = next + 2;
        if cursor >= body.len() {
            return None;
        }
    }
    None
}

async fn resolve_targets(db: &SqlitePool, model: &str) -> Result<Vec<String>, ApiError> {
    if let Some(combo) = store::get_combo(db, model).await? {
        return Ok(store::combo_models(&combo));
    }
    if model.contains('/') {
        return Ok(vec![model.to_string()]);
    }
    Err(ApiError::not_found(
        "Model not found; use provider/model or configure a combo",
    ))
}

async fn refresh_oauth_account(state: &AppState, provider: &mut Provider) -> Result<(), String> {
    refresh_oauth_account_with_force(state, provider, false).await
}

async fn refresh_oauth_account_with_force(
    state: &AppState,
    provider: &mut Provider,
    force: bool,
) -> Result<(), String> {
    if provider.auth_type != "oauth" {
        return Ok(());
    }
    let Some(connection_id) = provider.connection_id.clone() else {
        return Ok(());
    };
    let lock = {
        let mut locks = state.oauth_locks.lock().await;
        locks
            .entry(connection_id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = lock.lock().await;
    let row =
        sqlx::query("SELECT data,authType FROM providerConnections WHERE id=? AND isActive=1")
            .bind(&connection_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Err("OAuth account is no longer active".into());
    };
    use sqlx::Row;
    let auth_type: String = row.try_get("authType").unwrap_or_default();
    if auth_type != "oauth" {
        return Ok(());
    }
    let raw: String = row.try_get("data").unwrap_or_default();
    let mut data: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
    let specific = data
        .get("providerSpecificData")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let refresh_token = data["refreshToken"].as_str().unwrap_or_default();
    if refresh_token.is_empty() {
        return Ok(());
    }
    let token_url = specific["tokenUrl"]
        .as_str()
        .or(specific["refreshUrl"].as_str())
        .or(data["tokenUrl"].as_str())
        .or_else(|| match provider.id.as_str() {
            "claude" => Some("https://api.anthropic.com/v1/oauth/token"),
            "codex" => Some("https://auth.openai.com/oauth/token"),
            "gemini-cli" => Some("https://oauth2.googleapis.com/token"),
            _ => None,
        });
    let Some(token_url) = token_url else {
        return Ok(());
    };
    let expiry = data["expiresAt"]
        .as_str()
        .and_then(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|t| t.timestamp())
                .or_else(|| value.parse::<i64>().ok())
        })
        .or_else(|| data["expiresAt"].as_i64())
        .or_else(|| data["tokenExpiresAt"].as_i64())
        .map(|value| {
            if value > 10_000_000_000 {
                value / 1000
            } else {
                value
            }
        });
    if !force {
        let Some(expiry) = expiry else {
            return Ok(());
        };
        if expiry > chrono::Utc::now().timestamp() + 90 {
            provider.api_key = data["accessToken"]
                .as_str()
                .unwrap_or(&provider.api_key)
                .to_string();
            return Ok(());
        }
    }
    let client_id = specific["clientId"]
        .as_str()
        .or(specific["oauthClientId"].as_str())
        .or(data["clientId"].as_str())
        .or_else(|| match provider.id.as_str() {
            "claude" => Some("9d1c250a-e61b-44d9-88ed-5944d1962f5e"),
            "codex" => Some("app_EMoamEEZ73f0CkXaXp7hrann"),
            "gemini-cli" => {
                Some("681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com")
            }
            _ => None,
        });
    let client_secret = specific["clientSecret"]
        .as_str()
        .or(data["clientSecret"].as_str())
        .or_else(|| (provider.id == "gemini-cli").then_some("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"));
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
    ];
    if let Some(client_id) = client_id {
        form.push(("client_id", client_id.to_string()));
    }
    if let Some(client_secret) = client_secret {
        form.push(("client_secret", client_secret.to_string()));
    }
    let request = state
        .http
        .post(token_url)
        .header(header::ACCEPT, "application/json");
    let response = if provider.id == "claude" {
        request.json(&json!({"grant_type":"refresh_token","refresh_token":refresh_token,"client_id":client_id})).send().await
    } else {
        let encoded = serde_urlencoded::to_string(&form).map_err(|e| e.to_string())?;
        request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(encoded).send().await
    }.map_err(|e| format!("OAuth token refresh failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "OAuth token refresh returned HTTP {}",
            response.status()
        ));
    }
    let refreshed: Value = response
        .json()
        .await
        .map_err(|e| format!("Invalid OAuth refresh response: {e}"))?;
    let Some(access_token) = refreshed
        .get("access_token")
        .or_else(|| refreshed.get("accessToken"))
        .and_then(Value::as_str)
    else {
        return Err("OAuth refresh response did not contain an access token".into());
    };
    data["accessToken"] = json!(access_token);
    if let Some(rotated) = refreshed
        .get("refresh_token")
        .or_else(|| refreshed.get("refreshToken"))
        .and_then(Value::as_str)
    {
        data["refreshToken"] = json!(rotated);
    }
    if let Some(seconds) = refreshed
        .get("expires_in")
        .or_else(|| refreshed.get("expiresIn"))
        .and_then(Value::as_i64)
    {
        data["expiresAt"] =
            json!((chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339());
        data["expiresIn"] = json!(seconds);
    }
    let now = chrono::Utc::now().to_rfc3339();
    data["lastRefreshAt"] = json!(now);
    sqlx::query("UPDATE providerConnections SET data=?,updatedAt=? WHERE id=?")
        .bind(data.to_string())
        .bind(now)
        .bind(&connection_id)
        .execute(&state.db)
        .await
        .map_err(|e| e.to_string())?;
    provider.api_key = access_token.to_string();
    Ok(())
}

async fn send_upstream(
    state: &AppState,
    provider: &Provider,
    incoming_headers: &HeaderMap,
    method: Method,
    url: &str,
    original_body: Option<reqwest::Body>,
    body_is_json: bool,
    payload: &Value,
) -> Result<reqwest::Response, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    copy_request_headers(incoming_headers, &mut headers);
    match provider.api_format.as_str() {
        "anthropic" => {
            if !provider.api_key.is_empty() {
                let value = HeaderValue::from_str(&provider.api_key)
                    .map_err(|_| "Invalid upstream API key".to_string())?;
                if provider.auth_type == "oauth" {
                    headers.insert(
                        header::AUTHORIZATION,
                        HeaderValue::from_str(&format!("Bearer {}", provider.api_key))
                            .map_err(|_| "Invalid OAuth access token".to_string())?,
                    );
                    headers.insert(
                        "anthropic-beta",
                        HeaderValue::from_static("oauth-2025-04-20,claude-code-20250219"),
                    );
                    headers.insert(
                        "anthropic-dangerous-direct-browser-access",
                        HeaderValue::from_static("true"),
                    );
                } else {
                    headers.insert("x-api-key", value);
                }
            }
            headers
                .entry("anthropic-version")
                .or_insert(HeaderValue::from_static("2023-06-01"));
            if provider.auth_type != "oauth" {
                headers.remove(header::AUTHORIZATION);
            }
        }
        _ if !provider.api_key.is_empty() => {
            let value = HeaderValue::from_str(&format!("Bearer {}", provider.api_key))
                .map_err(|_| "Invalid upstream API key".to_string())?;
            headers.insert(header::AUTHORIZATION, value);
        }
        _ => {}
    }
    let settings = read_settings(&state.db)
        .await
        .map_err(|error| error.to_string())?;
    let provider_id = store::canonical_provider_id(&provider.id);
    if let Some(overrides) = settings["providerOverrides"][provider_id]["headers"].as_object() {
        for (name, value) in overrides {
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "host"
                    | "content-length"
                    | "content-type"
                    | "connection"
                    | "transfer-encoding"
                    | "authorization"
                    | "cookie"
            ) {
                continue;
            }
            let (Ok(name), Some(raw_value)) = (
                reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                value.as_str(),
            ) else {
                continue;
            };
            let Ok(value) = reqwest::header::HeaderValue::from_str(raw_value) else {
                continue;
            };
            headers.insert(name, value);
        }
    }
    let request = state.http.request(method, url).headers(headers);
    let request = if body_is_json {
        request.json(payload)
    } else if let Some(body) = original_body {
        request.body(body)
    } else {
        request
    };
    request.send().await.map_err(|e| e.to_string())
}

fn upstream_response(upstream: reqwest::Response) -> Response {
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for name in [
        "content-type",
        "cache-control",
        "retry-after",
        "x-request-id",
        "request-id",
        "anthropic-organization-id",
    ] {
        if let (Some(value), Ok(header_name)) = (
            upstream.headers().get(name),
            name.parse::<axum::http::HeaderName>(),
        ) {
            headers.insert(header_name, value.clone());
        }
    }
    let stream = upstream
        .bytes_stream()
        .map(|chunk| chunk.map_err(std::io::Error::other));
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-cache"));
    response
}

fn is_retryable(status: u16) -> bool {
    status == 408 || status == 409 || status == 429 || status >= 500
}

async fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
        })
        .or_else(|| {
            headers
                .get("x-goog-api-key")
                .and_then(|value| value.to_str().ok())
        });
    let Some(provided) = provided else {
        if state.api_key.is_none() {
            return Ok(());
        }
        return Err(ApiError::unauthorized("Missing or invalid API key"));
    };
    let stored: Option<i64> = sqlx::query_scalar("SELECT isActive FROM apiKeys WHERE key=?")
        .bind(provided)
        .fetch_optional(&state.db)
        .await?;
    if stored == Some(1) {
        Ok(())
    } else {
        match &state.api_key {
            Some(expected) if expected == provided => Ok(()),
            None if stored.is_some() => Err(ApiError::unauthorized("API key is inactive")),
            _ => Err(ApiError::unauthorized("Missing or invalid API key")),
        }
    }
}

async fn authorize_stored_key(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .or_else(|| headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()));
    if let Some(key) = provided {
        let active: Option<i64> = sqlx::query_scalar("SELECT isActive FROM apiKeys WHERE key=?")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
        if active == Some(1) {
            return Ok(());
        }
        if state.api_key.as_deref() == Some(key) {
            return Ok(());
        }
        return Err(ApiError::unauthorized("Missing or invalid API key"));
    }
    if state.api_key.is_none() {
        Ok(())
    } else {
        Err(ApiError::unauthorized("Missing or invalid API key"))
    }
}

async fn enforce_key_access(
    state: &AppState,
    headers: &HeaderMap,
    requested: &str,
) -> Result<(), ApiError> {
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .or_else(|| headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()));
    let Some(key) = key else {
        return Ok(());
    };
    let row: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT accessRestricted, accessAllow FROM apiKeys WHERE key=? AND isActive=1",
    )
    .bind(key)
    .fetch_optional(&state.db)
    .await?;
    let Some((1, allow_json)) = row else {
        return Ok(());
    };
    let allowed: Vec<String> = allow_json
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    if allowed
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(requested))
    {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        format!("This API key is not allowed to use model \"{requested}\""),
    ))
}

async fn restricted_key_allow(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Vec<String>>, ApiError> {
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .or_else(|| headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()));
    let Some(key) = key else {
        return Ok(None);
    };
    let row: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT accessRestricted, accessAllow FROM apiKeys WHERE key=? AND isActive=1",
    )
    .bind(key)
    .fetch_optional(&state.db)
    .await?;
    let Some((1, allow_json)) = row else {
        return Ok(None);
    };
    Ok(Some(
        allow_json
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default(),
    ))
}

fn endpoint_url(base: &str, path: &str, query: Option<&str>) -> Result<String, ApiError> {
    let parsed = reqwest::Url::parse(base.trim_end_matches('/'))
        .map_err(|_| ApiError::bad_request("Provider baseUrl must be an absolute HTTP(S) URL"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ApiError::bad_request(
            "Provider baseUrl must use HTTP or HTTPS",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ApiError::bad_request(
            "Provider baseUrl cannot include a query or fragment",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ApiError::bad_request(
            "Put provider credentials in the API key field, not the baseUrl",
        ));
    }
    let base_path = parsed.path().trim_end_matches('/');
    let route_path = path.trim_start_matches('/');
    let base_suffix = base_path.trim_start_matches('/');
    let mut url = base.trim_end_matches('/').to_string();
    if !base_suffix.is_empty() && route_path.starts_with(base_suffix) {
        let rest = route_path
            .strip_prefix(base_suffix)
            .unwrap_or_default()
            .trim_start_matches('/');
        if !rest.is_empty() {
            url.push('/');
            url.push_str(rest);
        }
    } else if let Some(rest) = route_path
        .strip_prefix("v1/")
        .filter(|_| base_path.ends_with("/v1"))
    {
        url.push('/');
        url.push_str(base_path.trim_start_matches('/'));
        url.push('/');
        url.push_str(rest);
    } else {
        url.push_str(base_path);
        url.push('/');
        url.push_str(route_path);
    }
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    Ok(url)
}

fn copy_request_headers(source: &HeaderMap, target: &mut reqwest::header::HeaderMap) {
    for (name, value) in source {
        if matches!(
            name.as_str(),
            "host" | "content-length" | "authorization" | "connection" | "transfer-encoding"
        ) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            target.insert(name, value);
        }
    }
}

fn validate_provider(input: &ProviderInput) -> Result<(), ApiError> {
    if input.id.as_deref().is_some_and(|id| !safe_id(id)) {
        return Err(ApiError::bad_request(
            "Provider id may contain only letters, numbers, '.', '_' and '-'",
        ));
    }
    if input.name.trim().is_empty() {
        return Err(ApiError::bad_request("Provider name is required"));
    }
    endpoint_url(&input.base_url, "v1/models", None)?;
    if !matches!(input.api_format.as_str(), "openai" | "anthropic") {
        return Err(ApiError::bad_request(
            "apiFormat must be 'openai' or 'anthropic'",
        ));
    }
    Ok(())
}

fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn provider_json(provider: Provider) -> Value {
    let models = store::models(&provider);
    json!({"id":provider.id,"name":provider.name,"baseUrl":provider.base_url,"apiFormat":provider.api_format,"models":models,"enabled":provider.enabled != 0,"hasApiKey":!provider.api_key.is_empty()})
}

fn combo_json(combo: crate::store::Combo) -> Value {
    let models = store::combo_models(&combo);
    json!({"id":combo.id,"name":combo.name,"models":models,"enabled":combo.enabled != 0})
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}
impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    fn upstream(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error":{"message":self.message,"type":"9router_error"}})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod usage_tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[test]
    fn claude_usage_maps_standard_and_scoped_windows() {
        let result = parse_claude_usage(&json!({
            "five_hour":{"utilization":87.5,"resets_at":"2026-10-21T13:00:00Z"},
            "seven_day":{"utilization":20.0},
            "seven_day_opus":{"utilization":10.0},
            "limits":[{"kind":"weekly_scoped","percent":120.0,"scope":{"model":{"display_name":"Opus"}}}]
        }));

        assert_eq!(result["plan"], "Claude Code");
        assert_eq!(result["quotas"]["session (5h)"]["used"], 87.5);
        assert_eq!(result["quotas"]["session (5h)"]["remaining"], 12.5);
        assert_eq!(
            result["quotas"]["session (5h)"]["resetAt"],
            "2026-10-21T13:00:00.000Z"
        );
        assert_eq!(result["quotas"]["weekly (7d)"]["used"], 20.0);
        assert_eq!(result["quotas"]["weekly opus (7d)"]["used"], 100.0);
    }

    #[test]
    fn claude_reset_grants_exclude_paused_and_empty_grants() {
        let grants = parse_claude_reset_grants(&json!({
            "eligible":true,
            "next_grant_id":"second",
            "grants":[
                {"id":"first","resets_left":1,"paused":true},
                {"id":"second","resets_left":2,"ends_at":"tomorrow","clears":["session"]},
                {"id":"empty","resets_left":0}
            ]
        }));

        assert_eq!(grants["availableCount"], 2.0);
        assert_eq!(grants["nextGrantId"], "second");
        assert_eq!(grants["expiresAt"], "tomorrow");
        assert_eq!(grants["grants"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn codex_usage_maps_primary_review_and_spark_windows() {
        let result = parse_codex_usage(&json!({
            "plan_type":"plus",
            "rate_limit":{"limit_reached":true,"primary_window":{"used_percent":101,"reset_at":123}},
            "additional_rate_limits":[
                {"limit_name":"code_review","rate_limit":{"primary_window":{"percent_used":25}}},
                {"limit_name":"gpt-5.3-codex-spark","rate_limit":{"secondary_window":{"used_percent":30}}}
            ],
            "rate_limit_reset_credits":{"available_count":3}
        }));

        assert_eq!(result["plan"], "plus");
        assert_eq!(result["limitReached"], true);
        assert_eq!(result["resetCredits"]["availableCount"], 3.0);
        assert_eq!(result["quotas"]["session"]["used"], 100.0);
        assert_eq!(
            result["quotas"]["session"]["resetAt"],
            "1970-01-01T00:02:03.000Z"
        );
        assert_eq!(result["quotas"]["review_session"]["used"], 25.0);
        assert_eq!(result["quotas"]["spark_weekly"]["used"], 30.0);
    }

    #[test]
    fn reset_time_normalizes_seconds_milliseconds_and_invalid_values() {
        assert_eq!(
            parse_reset_time(&json!(1_800_000_000)),
            "2027-01-15T08:00:00.000Z"
        );
        assert_eq!(
            parse_reset_time(&json!(1_800_000_000_000_i64)),
            "2027-01-15T08:00:00.000Z"
        );
        assert!(parse_reset_time(&json!("not-a-date")).is_null());
    }

    #[test]
    fn usage_cache_key_uses_a_digest_instead_of_the_access_token() {
        let key = usage_cache_key("claude", "sensitive-token");
        assert!(key.starts_with("claude:"));
        assert!(!key.contains("sensitive-token"));
    }

    #[tokio::test]
    async fn unsupported_usage_provider_signals_the_node_compatibility_route() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        store::initialize(&db).await.unwrap();
        sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind("usage-test")
            .bind("unsupported-provider")
            .bind("oauth")
            .bind("Test")
            .bind(Option::<String>::None)
            .bind(Option::<i64>::None)
            .bind(1_i64)
            .bind("{}")
            .bind("2026-10-21T00:00:00Z")
            .bind("2026-10-21T00:00:00Z")
            .execute(&db)
            .await
            .unwrap();
        let state = AppState {
            db,
            http: reqwest::Client::new(),
            api_key: None,
            auth_secret: Arc::new(b"test-secret".to_vec()),
            login_attempts: Default::default(),
            oauth_locks: Default::default(),
            mcp_entries: Default::default(),
            console_logs: ConsoleLogBuffer::new(),
        };

        let response = api_connection_usage(
            State(state),
            HeaderMap::new(),
            Path("usage-test".to_string()),
            OriginalUri(axum::http::Uri::from_static("/api/usage/usage-test")),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(response.headers()["x-9router-fallback"], "node");
    }
}
