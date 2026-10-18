use std::time::Instant;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
};
use bytes::Bytes;
use futures_util::StreamExt;
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
        .with_state(state)
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
    let nodes: Vec<Value> = store::list_providers(&state.db).await?.into_iter().map(|provider| {
        json!({"id":provider.id,"provider":provider.id,"name":provider.name,"baseUrl":provider.base_url,"authType":"apikey","isActive":true})
    }).collect();
    Ok(Json(json!({"connections":nodes})))
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
