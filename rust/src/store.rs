use serde::Deserialize;
use sqlx::{FromRow, SqlitePool};

#[derive(Clone, Debug, FromRow)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub api_key: String,
    pub api_format: String,
    pub models_json: String,
    pub enabled: i64,
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
    Ok(())
}

pub async fn list_providers(db: &SqlitePool) -> Result<Vec<Provider>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,provider,name,authType,isActive,priority,data FROM providerConnections WHERE isActive=1 ORDER BY COALESCE(priority,999),updatedAt")
        .fetch_all(db).await?;
    use sqlx::Row;
    let mut providers = Vec::new();
    for row in rows {
        let data: serde_json::Value =
            serde_json::from_str(&row.get::<String, _>("data")).unwrap_or_default();
        let provider = row.get::<String, _>("provider");
        let id = row.get::<String, _>("id");
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
        let api_key = data
            .get("apiKey")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let api_format =
            if provider == "anthropic" || provider.starts_with("anthropic-compatible-") {
                "anthropic"
            } else {
                "openai"
            }
            .to_string();
        let base_url = if base_url.is_empty() {
            provider_specific
                .get("baseUrl")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        } else {
            base_url
        };
        let models_json = serde_json::to_string(
            provider_specific
                .get("enabledModels")
                .unwrap_or(&serde_json::Value::Array(vec![])),
        )
        .unwrap_or_else(|_| "[]".into());
        providers.push(Provider {
            id,
            name: row.get::<Option<String>, _>("name").unwrap_or(provider),
            base_url,
            api_key,
            api_format,
            models_json,
            enabled: 1,
        });
    }
    // Compatible custom provider nodes live in the same established schema.
    let nodes = sqlx::query("SELECT id,type,name,data FROM providerNodes WHERE type IN ('openai-compatible','anthropic-compatible')")
        .fetch_all(db).await?;
    for row in nodes {
        let data: serde_json::Value =
            serde_json::from_str(&row.get::<String, _>("data")).unwrap_or_default();
        let kind = row.get::<Option<String>, _>("type").unwrap_or_default();
        let mut models = data
            .get("models")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        let custom: Vec<String> =
            sqlx::query_scalar("SELECT value FROM kv WHERE scope='customModels' AND key LIKE ?")
                .bind(format!("{}|%", row.get::<String, _>("id")))
                .fetch_all(db)
                .await?
                .into_iter()
                .filter_map(|v: String| {
                    serde_json::from_str::<serde_json::Value>(&v)
                        .ok()?
                        .get("id")?
                        .as_str()
                        .map(str::to_owned)
                })
                .collect();
        if let Some(models) = models.as_array_mut() {
            models.extend(custom.into_iter().map(serde_json::Value::String));
        } else {
            models = serde_json::json!(custom);
        }
        providers.push(Provider {
            id: row.get("id"),
            name: row
                .get::<Option<String>, _>("name")
                .unwrap_or_else(|| "Custom provider".into()),
            base_url: data
                .get("baseUrl")
                .or_else(|| data.get("baseURL"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            api_key: data
                .get("apiKey")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            api_format: if kind == "anthropic-compatible" {
                "anthropic"
            } else {
                "openai"
            }
            .into(),
            models_json: serde_json::to_string(&models).unwrap_or_else(|_| "[]".into()),
            enabled: 1,
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
    let id = match input.id.filter(|id| !id.trim().is_empty()) {
        Some(id) => id,
        None => available_provider_id(db, &input.name).await?,
    };
    let now = chrono_stub_now();
    let current: Option<(String, String, String, String)> =
        sqlx::query_as("SELECT provider,authType,name,data FROM providerConnections WHERE id=?")
            .bind(&id)
            .fetch_optional(db)
            .await?;
    let (provider, auth_type, name, mut data) = current
        .map(|(p, a, n, d)| {
            (
                p,
                a,
                n,
                serde_json::from_str::<serde_json::Value>(&d).unwrap_or_default(),
            )
        })
        .unwrap_or_else(|| {
            (
                id.clone(),
                "apikey".into(),
                input.name.clone(),
                serde_json::json!({}),
            )
        });
    data["providerSpecificData"]["baseUrl"] = serde_json::json!(input.base_url);
    if !input.api_key.is_empty() {
        data["apiKey"] = serde_json::json!(input.api_key);
    }
    data["providerSpecificData"]["enabledModels"] = serde_json::json!(input.models);
    sqlx::query("INSERT INTO providerConnections(id,provider,authType,name,isActive,data,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET isActive=excluded.isActive,data=excluded.data,updatedAt=excluded.updatedAt")
        .bind(&id).bind(&provider).bind(&auth_type).bind(&name).bind(if input.enabled {1_i64} else {0_i64}).bind(data.to_string()).bind(&now).bind(&now).execute(db).await?;
    get_provider(db, &id).await?.ok_or(sqlx::Error::RowNotFound)
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
    let result = sqlx::query("DELETE FROM providerConnections WHERE id=?")
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
