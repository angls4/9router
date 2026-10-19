use std::time::Instant;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{
        Html, IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{any, get},
};
use bytes::Bytes;
use chrono::Timelike;
use futures_util::StreamExt;
use hmac::Mac;
use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::store::{self, ComboInput, Provider, ProviderInput};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub http: reqwest::Client,
    pub api_key: Option<String>,
    pub oauth_locks: Arc<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    pub mcp_entries: Arc<tokio::sync::Mutex<HashMap<String, McpEntry>>>,
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
        .route("/admin/providers", get(list_providers).put(save_provider))
        .route("/api/providers/client", get(api_models))
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
            "/api/provider-nodes",
            get(api_list_provider_nodes).post(api_create_provider_node),
        )
        .route(
            "/api/provider-nodes/{id}",
            axum::routing::put(api_update_provider_node).delete(api_delete_provider_node),
        )
        .route(
            "/api/models",
            get(api_dashboard_models).put(set_dashboard_model_alias),
        )
        .route("/api/combos", get(api_list_combos).post(api_create_combo))
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
            "/api/media-providers/tts/{provider}/voices",
            get(api_media_tts_voices),
        )
        .route("/api/mcp/{plugin}/sse", get(api_mcp_sse))
        .route(
            "/api/mcp/{plugin}/message",
            axum::routing::post(api_mcp_message),
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
        .route("/v1", any(proxy_root))
        .route("/api/v1", any(proxy_root))
        .route("/api/v1/{*path}", any(proxy))
        .route("/v1/{*path}", any(proxy))
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            protect_dashboard_api,
        ))
        .with_state(state)
}

async fn protect_dashboard_api(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let is_dashboard_api =
        path.starts_with("/api/") && !path.starts_with("/api/v1/") && path != "/api/health";
    if is_dashboard_api {
        if let Some(expected) = state.api_key.as_deref() {
            let provided = request
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
            if provided != Some(expected) {
                return ApiError::unauthorized("Missing or invalid API key").into_response();
            }
        }
    }
    next.run(request).await
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
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
    let mut models = Vec::new();
    for p in store::list_providers(&s.db).await? {
        let disabled_ids = disabled
            .get(&p.id)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for model in store::models(&p) {
            if disabled_ids.iter().any(|v| v.as_str() == Some(&model)) {
                continue;
            }
            let full = format!("{}/{}", p.id, model);
            models.push(json!({"provider":p.id,"model":model,"name":model,"fullModel":full,"routedModel":full,"alias":aliases.get(&full).and_then(Value::as_str).unwrap_or(&model),"caps":{"vision":false,"search":false,"reasoning":false}}));
        }
    }
    Ok(Json(json!({"models":models})))
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
        Bytes::from(serde_json::to_vec(&body).map_err(|e| ApiError::bad_request(e.to_string()))?),
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
    body: Bytes,
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
    let body_is_json =
        content_type.contains("json") || body.first().is_some_and(|b| *b == b'{' || *b == b'[');
    let request_json: Value = if body_is_json && !body.is_empty() {
        serde_json::from_slice(&body)
            .map_err(|_| ApiError::bad_request("Request body must be valid JSON"))?
    } else {
        json!({})
    };
    let multipart_range = multipart_field_range(content_type, &body, "model");
    let requested_model = request_json
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            multipart_range
                .as_ref()
                .and_then(|range| String::from_utf8(body[range.clone()].to_vec()).ok())
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
        let mut outbound_body = body.to_vec();
        if let Some(range) = &multipart_range {
            outbound_body.splice(range.clone(), model.bytes());
        }
        match send_upstream(
            &state,
            &provider,
            &headers,
            method.clone(),
            &upstream_url,
            &outbound_body,
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
    body: Bytes,
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
    original_body: &[u8],
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
    let request = state.http.request(method, url).headers(headers);
    let request = if original_body.is_empty() {
        request
    } else if body_is_json {
        request.json(payload)
    } else {
        request.body(original_body.to_vec())
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
