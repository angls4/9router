use std::time::Instant;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
};
use bytes::Bytes;
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
    let mut candidates = Vec::new();
    let providers = store::list_providers(&state.db).await?;
    for target in &targets {
        let (provider_id, model) = target
            .split_once('/')
            .ok_or_else(|| ApiError::bad_request("Targets must use provider/model format"))?;
        for provider in providers
            .iter()
            .filter(|provider| provider.id == provider_id)
        {
            let available = store::models(provider);
            if !available.is_empty() && !available.iter().any(|item| item == model) {
                continue;
            }
            candidates.push((target.clone(), provider.clone(), model.to_string()));
        }
    }
    let mut last_error: Option<String> = None;
    for (index, (target, provider, model)) in candidates.iter().enumerate() {
        let mut outbound = payload.clone();
        if let Some(obj) = outbound.as_object_mut() {
            obj.insert("model".into(), Value::String(model.to_string()));
        }
        let upstream_path = format!(
            "{}/{}",
            provider.api_path_prefix.trim_matches('/'),
            path.trim_start_matches('/')
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
                if is_retryable(status) && index + 1 < candidates.len() {
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
                headers.insert("x-api-key", value);
            }
            headers
                .entry("anthropic-version")
                .or_insert(HeaderValue::from_static("2023-06-01"));
            headers.remove(header::AUTHORIZATION);
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
