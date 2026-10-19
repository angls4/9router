use serde::Deserialize;
use sqlx::{FromRow, SqlitePool};

#[derive(Clone, Debug, FromRow)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub api_path_prefix: String,
    pub api_key: String,
    pub api_format: String,
    pub models_json: String,
    pub enabled: i64,
    pub connection_id: Option<String>,
    pub auth_type: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryProvider {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    format: String,
    base_url: String,
    #[serde(default)]
    path_prefix: String,
    #[serde(default)]
    models: Vec<String>,
}

fn registry_providers() -> &'static [RegistryProvider] {
    static PROVIDERS: std::sync::OnceLock<Vec<RegistryProvider>> = std::sync::OnceLock::new();
    PROVIDERS
        .get_or_init(|| serde_json::from_str(include_str!("../providers.json")).unwrap_or_default())
}

fn registry_provider(id: &str) -> Option<&'static RegistryProvider> {
    registry_providers()
        .iter()
        .find(|provider| provider.id == id || provider.aliases.iter().any(|alias| alias == id))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInput {
    pub id: Option<String>,
    pub name: String,
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_format")]
    pub api_format: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

#[derive(Clone, Debug, FromRow)]
pub struct Combo {
    pub id: String,
    pub name: String,
    pub models_json: String,
    pub enabled: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComboInput {
    pub id: Option<String>,
    pub name: String,
    pub models: Vec<String>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

fn default_format() -> String {
    "openai".into()
}
fn enabled_by_default() -> bool {
    true
}

pub async fn initialize(db: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA journal_mode=WAL").execute(db).await?;
    // Native 9Router schema: credentials and provider options are stored in
    // providerConnections.data JSON, while compatible endpoints use providerNodes.
    sqlx::query("CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .execute(db)
        .await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS providerConnections (id TEXT PRIMARY KEY, provider TEXT NOT NULL, authType TEXT NOT NULL, name TEXT, email TEXT, priority INTEGER, isActive INTEGER DEFAULT 1, data TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL)")
        .execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS providerNodes (id TEXT PRIMARY KEY, type TEXT, name TEXT, data TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL)")
        .execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS combos (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT, models TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL)")
        .execute(db).await?;
    let _ = sqlx::query("ALTER TABLE combos ADD COLUMN kind TEXT")
        .execute(db)
        .await;
    sqlx::query("CREATE TABLE IF NOT EXISTS apiKeys (id TEXT PRIMARY KEY, key TEXT UNIQUE NOT NULL, name TEXT, machineId TEXT, isActive INTEGER DEFAULT 1, createdAt TEXT NOT NULL, accessRestricted INTEGER DEFAULT 0, accessAllow TEXT)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS kv (scope TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(scope,key))").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS request_log (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, requested_model TEXT NOT NULL, routed_model TEXT NOT NULL, status INTEGER NOT NULL, elapsed_ms INTEGER NOT NULL)")
        .execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS usageHistory (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, provider TEXT, model TEXT, connectionId TEXT, apiKey TEXT, endpoint TEXT, promptTokens INTEGER DEFAULT 0, completionTokens INTEGER DEFAULT 0, cost REAL DEFAULT 0, status TEXT, tokens TEXT, meta TEXT)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS requestDetails (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, provider TEXT, model TEXT, connectionId TEXT, status TEXT, data TEXT NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS proxyPools (id TEXT PRIMARY KEY, isActive INTEGER DEFAULT 1, testStatus TEXT, data TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL)").execute(db).await?;
    Ok(())
}

pub async fn list_providers(db: &SqlitePool) -> Result<Vec<Provider>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,provider,name,authType,isActive,priority,data FROM providerConnections WHERE isActive=1 AND authType='apikey' ORDER BY COALESCE(priority,999),updatedAt")
        .fetch_all(db).await?;
    use sqlx::Row;
    let mut providers = Vec::new();
    for row in rows {
        let data: serde_json::Value =
            serde_json::from_str(&row.get::<String, _>("data")).unwrap_or_default();
        let provider = row.get::<String, _>("provider");
        let provider_specific = data
            .get("providerSpecificData")
            .cloned()
            .unwrap_or_default();
        let base_url = provider_specific
            .get("baseUrl")
            .or_else(|| data.get("baseUrl"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let registry = registry_provider(&provider);
        let base_url = if base_url.is_empty() {
            registry
                .map(|definition| definition.base_url.clone())
                .unwrap_or_default()
        } else {
            base_url
        };
        let api_path_prefix = provider_specific
            .get("apiPathPrefix")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or_else(|| registry.map(|definition| definition.path_prefix.clone()))
            .unwrap_or_else(|| "/v1".into());
        let api_key = data
            .get("apiKey")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let api_format = if provider_specific
            .get("apiFormat")
            .and_then(serde_json::Value::as_str)
            == Some("anthropic")
            || provider == "anthropic"
            || provider.starts_with("anthropic-compatible-")
            || registry.is_some_and(|definition| definition.format == "claude")
        {
            "anthropic"
        } else {
            "openai"
        }
        .to_string();
        let configured_models = provider_specific
            .get("enabledModels")
            .and_then(serde_json::Value::as_array);
        let models = if configured_models.is_some_and(|models| !models.is_empty()) {
            configured_models.cloned().unwrap_or_default()
        } else {
            registry
                .map(|definition| {
                    definition
                        .models
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect()
                })
                .unwrap_or_default()
        };
        let models_json = serde_json::to_string(&models).unwrap_or_else(|_| "[]".into());
        providers.push(Provider {
            id: provider.clone(),
            name: row.get::<Option<String>, _>("name").unwrap_or(provider),
            base_url,
            api_path_prefix,
            api_key,
            api_format,
            models_json,
            enabled: 1,
            connection_id: Some(row.get::<String, _>("id")),
            auth_type: "apikey".into(),
        });
    }
    Ok(providers)
}

/// Credentials available to inference routing, including stored OAuth and
/// imported access-token accounts. OAuth providers with nonstandard payloads
/// still need a provider adapter; this list covers compatible endpoints.
pub async fn list_routing_accounts(db: &SqlitePool) -> Result<Vec<Provider>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT id,provider,name,authType,isActive,priority,data FROM providerConnections WHERE isActive=1 AND authType IN ('apikey','api_key','oauth','access_token') ORDER BY COALESCE(priority,999),updatedAt")
        .fetch_all(db).await?;
    let mut providers = Vec::new();
    for row in rows {
        let data: serde_json::Value =
            serde_json::from_str(&row.get::<String, _>("data")).unwrap_or_default();
        let provider_id = row.get::<String, _>("provider");
        let auth_type = row.get::<String, _>("authType");
        let specific = data
            .get("providerSpecificData")
            .cloned()
            .unwrap_or_default();
        let registry = registry_provider(&provider_id);
        let base_url = specific
            .get("baseUrl")
            .or_else(|| data.get("baseUrl"))
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                specific
                    .get("apiServerUrl")
                    .and_then(serde_json::Value::as_str)
            })
            .or_else(|| registry.map(|p| p.base_url.as_str()))
            .or_else(|| (provider_id == "claude").then_some("https://api.anthropic.com"))
            .unwrap_or_default()
            .to_string();
        if base_url.is_empty() {
            continue;
        }
        let api_path_prefix = specific
            .get("apiPathPrefix")
            .and_then(serde_json::Value::as_str)
            .or_else(|| registry.map(|p| p.path_prefix.as_str()))
            .or_else(|| (provider_id == "claude").then_some("/v1"))
            .unwrap_or("/v1")
            .to_string();
        let token = if auth_type == "apikey" || auth_type == "api_key" {
            data.get("apiKey").or_else(|| data.get("accessToken"))
        } else {
            data.get("accessToken")
        }
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
        if token.is_empty() {
            continue;
        }
        let format = specific
            .get("apiFormat")
            .and_then(serde_json::Value::as_str);
        let api_format = if format == Some("anthropic")
            || provider_id == "anthropic"
            || provider_id.starts_with("anthropic-compatible-")
            || registry.is_some_and(|p| p.format == "claude")
        {
            "anthropic"
        } else {
            "openai"
        };
        let configured = specific
            .get("enabledModels")
            .and_then(serde_json::Value::as_array);
        let models = configured
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| {
                registry
                    .map(|p| {
                        p.models
                            .iter()
                            .cloned()
                            .map(serde_json::Value::String)
                            .collect()
                    })
                    .unwrap_or_default()
            });
        providers.push(Provider {
            id: provider_id.clone(),
            name: row.get::<Option<String>, _>("name").unwrap_or(provider_id),
            base_url,
            api_path_prefix,
            api_key: token,
            api_format: api_format.to_string(),
            models_json: serde_json::to_string(&models).unwrap_or_else(|_| "[]".into()),
            enabled: 1,
            connection_id: Some(row.get::<String, _>("id")),
            auth_type,
        });
    }
    Ok(providers)
}

async fn available_provider_id(db: &SqlitePool, name: &str) -> Result<String, sqlx::Error> {
    let mut slug = String::new();
    let mut dash_pending = false;
    for character in name.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            if dash_pending && !slug.is_empty() {
                slug.push('-');
            }
            slug.push(character);
            dash_pending = false;
        } else {
            dash_pending = true;
        }
        if slug.len() >= 48 {
            break;
        }
    }
    if slug.is_empty() {
        slug.push_str("provider");
    }
    let mut candidate = slug.clone();
    let mut suffix = 2;
    loop {
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM providerConnections WHERE id=?")
            .bind(&candidate)
            .fetch_one(db)
            .await?;
        if exists == 0 {
            return Ok(candidate);
        }
        candidate = format!("{slug}-{suffix}");
        suffix += 1;
    }
}

pub async fn get_provider(db: &SqlitePool, id: &str) -> Result<Option<Provider>, sqlx::Error> {
    Ok(list_providers(db).await?.into_iter().find(|p| p.id == id))
}

pub async fn save_provider(db: &SqlitePool, input: ProviderInput) -> Result<Provider, sqlx::Error> {
    let requested_id = match input.id.filter(|id| !id.trim().is_empty()) {
        Some(id) => id,
        None => available_provider_id(db, &input.name).await?,
    };
    let now = chrono_stub_now();
    let current: Option<(String, String, String, String, String)> =
        sqlx::query_as("SELECT id,provider,authType,name,data FROM providerConnections WHERE id=? OR provider=? ORDER BY COALESCE(priority,999) LIMIT 1")
            .bind(&requested_id).bind(&requested_id)
            .fetch_optional(db)
            .await?;
    let (id, provider, auth_type, name, mut data) = current
        .map(|(row_id, p, a, n, d)| {
            (
                row_id,
                p,
                a,
                n,
                serde_json::from_str::<serde_json::Value>(&d).unwrap_or_default(),
            )
        })
        .unwrap_or_else(|| {
            (
                requested_id.clone(),
                requested_id.clone(),
                "apikey".into(),
                input.name.clone(),
                serde_json::json!({}),
            )
        });
    data["providerSpecificData"]["baseUrl"] = serde_json::json!(input.base_url);
    data["providerSpecificData"]["apiFormat"] = serde_json::json!(input.api_format);
    if !input.api_key.is_empty() {
        data["apiKey"] = serde_json::json!(input.api_key);
    }
    data["providerSpecificData"]["enabledModels"] = serde_json::json!(input.models);
    sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,isActive,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET isActive=excluded.isActive,data=excluded.data,updatedAt=excluded.updatedAt")
        .bind(&id).bind(&provider).bind(&auth_type).bind(&name).bind(if input.enabled {1_i64} else {0_i64}).bind(data.to_string()).bind(&now).bind(&now).execute(db).await?;
    get_provider(db, &provider)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

fn chrono_stub_now() -> String {
    // RFC3339 UTC timestamp without an additional runtime dependency.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}

pub async fn delete_provider(db: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM providerConnections WHERE id=? OR provider=?")
        .bind(id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_combos(db: &SqlitePool) -> Result<Vec<Combo>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,name,models,kind FROM combos ORDER BY createdAt")
        .fetch_all(db)
        .await?;
    use sqlx::Row;
    Ok(rows
        .into_iter()
        .map(|row| Combo {
            id: row.get("id"),
            name: row.get("name"),
            models_json: row.get("models"),
            enabled: 1,
        })
        .collect())
}

pub async fn get_combo(db: &SqlitePool, name: &str) -> Result<Option<Combo>, sqlx::Error> {
    Ok(list_combos(db).await?.into_iter().find(|c| c.name == name))
}

pub async fn save_combo(db: &SqlitePool, input: ComboInput) -> Result<Combo, sqlx::Error> {
    let requested_id = input.id.filter(|id| !id.trim().is_empty());
    let models = serde_json::to_string(&input.models).unwrap_or_else(|_| "[]".into());
    let _enabled = input.enabled;
    let name = input.name;
    let existing = if let Some(id) = requested_id.as_deref() {
        sqlx::query_as::<_, Combo>(
            "SELECT id,name,models AS models_json,1 AS enabled FROM combos WHERE id=?",
        )
        .bind(id)
        .fetch_optional(db)
        .await?
    } else {
        None
    };
    let existing = match existing {
        Some(combo) => Some(combo),
        None => {
            sqlx::query_as::<_, Combo>(
                "SELECT id,name,models AS models_json,1 AS enabled FROM combos WHERE name=?",
            )
            .bind(&name)
            .fetch_optional(db)
            .await?
        }
    };
    let id = existing
        .map(|combo| combo.id)
        .or(requested_id)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let now = chrono_stub_now();
    sqlx::query("INSERT INTO combos (id,name,kind,models,createdAt,updatedAt) VALUES (?,?,NULL,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,models=excluded.models,updatedAt=excluded.updatedAt")
        .bind(&id).bind(&name).bind(models).bind(&now).bind(&now).execute(db).await?;
    sqlx::query_as::<_, Combo>(
        "SELECT id,name,models AS models_json,1 AS enabled FROM combos WHERE id=?",
    )
    .bind(id)
    .fetch_one(db)
    .await
}

pub async fn delete_combo(db: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM combos WHERE id=? OR name=?")
        .bind(id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn log_request(
    db: &SqlitePool,
    requested: &str,
    routed: &str,
    status: u16,
    elapsed_ms: u128,
) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let status_text = if status < 400 { "ok" } else { "error" };
    let (provider, model) = routed.split_once('/').unwrap_or(("", requested));
    let metadata = serde_json::json!({"elapsedMs":elapsed_ms.min(i64::MAX as u128) as i64,"routedModel":routed}).to_string();
    let _ = sqlx::query("INSERT INTO usageHistory(timestamp,provider,model,endpoint,promptTokens,completionTokens,cost,status,tokens,meta) VALUES(?,?,?,?,0,0,0,?,?,?)")
        .bind(timestamp).bind(if provider.is_empty(){None}else{Some(provider)}).bind(model).bind("Rust Gateway").bind(status_text).bind("{}").bind(metadata).execute(db).await;
    let _ = sqlx::query(
        "INSERT INTO request_log(requested_model,routed_model,status,elapsed_ms) VALUES(?,?,?,?)",
    )
    .bind(requested)
    .bind(routed)
    .bind(i64::from(status))
    .bind(elapsed_ms.min(i64::MAX as u128) as i64)
    .execute(db)
    .await;
}

pub async fn recent_requests(
    db: &SqlitePool,
    limit: i64,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows = sqlx::query("SELECT created_at,requested_model,routed_model,status,elapsed_ms FROM request_log ORDER BY id DESC LIMIT ?")
        .bind(limit.clamp(1, 200)).fetch_all(db).await?;
    use sqlx::Row;
    Ok(rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "createdAt": row.get::<String, _>("created_at"),
                "requestedModel": row.get::<String, _>("requested_model"),
                "routedModel": row.get::<String, _>("routed_model"),
                "status": row.get::<i64, _>("status"),
                "elapsedMs": row.get::<i64, _>("elapsed_ms")
            })
        })
        .collect())
}

pub fn models(provider: &Provider) -> Vec<String> {
    serde_json::from_str(&provider.models_json).unwrap_or_default()
}

pub fn combo_models(combo: &Combo) -> Vec<String> {
    serde_json::from_str(&combo.models_json).unwrap_or_default()
}
