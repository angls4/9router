#![recursion_limit = "256"]

mod auth;
mod console_logs;
mod server;
mod store;

use console_logs::{ConsoleLogBuffer, ConsoleLogLayer};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{EnvFilter, prelude::*};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let console_logs = ConsoleLogBuffer::new();
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .with(ConsoleLogLayer::new(console_logs.clone()))
        .init();

    let data_dir = env::var_os("DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".9router")))
        .unwrap_or_else(|| PathBuf::from("./data"));
    tokio::fs::create_dir_all(&data_dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    // Share the established Node application's SQLite database so the Rust
    // gateway can use existing provider accounts, API keys, settings, and combos.
    let db_dir = data_dir.join("db");
    tokio::fs::create_dir_all(&db_dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&db_dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    let db_path = db_dir.join("data.sqlite");
    let options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    store::initialize(&pool).await?;
    let auth_secret = load_auth_secret(&data_dir).await?;

    let state = server::AppState {
        db: pool,
        http: reqwest::Client::builder().build()?,
        api_key: env::var("NINEROUTER_API_KEY")
            .ok()
            .filter(|key| !key.is_empty()),
        auth_secret: Arc::new(auth_secret),
        login_attempts: Default::default(),
        oauth_locks: Default::default(),
        mcp_entries: Default::default(),
        console_logs,
    };
    tokio::spawn(server::catalog_sync_scheduler());
    let app = server::router(state).layer(TraceLayer::new_for_http());
    let addr: SocketAddr = format!(
        "{}:{}",
        env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        env::var("PORT").unwrap_or_else(|_| "20127".into())
    )
    .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "9Router Rust gateway listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn load_auth_secret(
    data_dir: &std::path::Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Ok(secret) = env::var("JWT_SECRET") {
        return Ok(secret.into_bytes());
    }
    let secret_path = data_dir.join("jwt-secret");
    let secret = match tokio::fs::read_to_string(&secret_path).await {
        Ok(secret) => secret.trim().to_string(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let secret = format!(
                "{}{}{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple(),
            );
            tokio::fs::write(&secret_path, &secret).await?;
            secret
        }
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(secret.into_bytes())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
