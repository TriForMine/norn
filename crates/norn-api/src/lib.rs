use std::{net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use norn_core::{IgnoredFinding, NotificationEvent, Notifier, RiskLevel, ScanRunner};
use norn_db::Database;
use norn_notify::DiscordNotifier;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

#[derive(Clone)]
pub struct ApiState {
    pub db: Database,
    pub runner: Option<Arc<dyn ScanRunner>>,
    pub notifier: Option<Arc<dyn Notifier>>,
}

impl ApiState {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            runner: None,
            notifier: None,
        }
    }
}

pub async fn serve(bind: &str, static_dir: &str, state: ApiState) -> Result<()> {
    let app = router(state, static_dir);
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind HTTP server to {bind}"))?;
    tracing::info!(bind, "Norn API listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("HTTP server failed")
}

pub fn router(state: ApiState, static_dir: impl AsRef<Path>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/summary", get(summary))
        .route("/inventory", get(inventory))
        .route("/services", get(services))
        .route("/vulnerabilities", get(vulnerabilities))
        .route("/scans", get(scans))
        .route("/scans/run", post(run_scan))
        .route("/ignore", post(ignore))
        .route("/notifications/test", post(test_notification))
        .with_state(state.clone());

    let app = Router::new()
        .nest("/api", api)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let index = static_dir.as_ref().join("index.html");
    if index.exists() {
        app.fallback_service(ServeDir::new(static_dir))
    } else {
        app.route("/", get(dashboard_placeholder))
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "project": "norn",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn summary(State(state): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(state.db.summary()?)))
}

async fn inventory(State(state): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(state.db.latest_inventory()?)))
}

async fn services(State(state): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(state.db.service_summaries()?)))
}

async fn vulnerabilities(State(state): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(state.db.vulnerability_summaries()?)))
}

async fn scans(State(state): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(state.db.list_scans()?)))
}

async fn run_scan(State(state): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    let runner = state
        .runner
        .ok_or_else(|| ApiError::bad_request("scan runner is not configured"))?;
    let outcome = runner.run_scan().await?;
    Ok(Json(json!(outcome)))
}

#[derive(Debug, Deserialize)]
struct IgnoreRequest {
    vulnerability_id: String,
    service: Option<String>,
    days: Option<i64>,
    reason: Option<String>,
}

async fn ignore(
    State(state): State<ApiState>,
    Json(request): Json<IgnoreRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let ignore = IgnoredFinding {
        vulnerability_id: request.vulnerability_id,
        service: request.service,
        expires_at: request.days.map(|days| Utc::now() + Duration::days(days)),
        reason: request.reason,
    };
    state.db.add_ignore(&ignore)?;
    Ok(Json(json!({ "status": "ignored", "ignore": ignore })))
}

#[derive(Debug, Deserialize)]
struct TestNotificationRequest {
    webhook_url: Option<String>,
}

async fn test_notification(
    State(state): State<ApiState>,
    Json(request): Json<TestNotificationRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let event = NotificationEvent {
        project: "Norn".to_string(),
        host: "test-host".to_string(),
        service: "notification-test".to_string(),
        artifact: Some("norn".to_string()),
        vulnerability_id: Some("TEST-NOTIFICATION".to_string()),
        severity: None,
        runtime_risk: RiskLevel::High,
        exposure: norn_core::Exposure::Unknown,
        reason: "Discord webhook test from Norn".to_string(),
        recommended_action: Some("No action required.".to_string()),
    };

    if let Some(webhook_url) = request.webhook_url.filter(|url| !url.trim().is_empty()) {
        DiscordNotifier::new(webhook_url).send(event).await?;
    } else {
        let notifier = state
            .notifier
            .ok_or_else(|| ApiError::bad_request("notification adapter is not configured"))?;
        notifier.send(event).await?;
    }

    Ok(Json(json!({ "status": "sent" })))
}

async fn dashboard_placeholder() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Norn</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
    main { max-width: 880px; margin: 12vh auto; padding: 0 24px; }
    code { background: #1e293b; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <main>
    <h1>Norn API is running</h1>
    <p>Build the dashboard with <code>cd apps/web && npm install && npm run build</code>, or use <code>/api/summary</code>.</p>
  </main>
</body>
</html>"#,
    )
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.into().to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}
