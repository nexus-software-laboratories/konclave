use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

#[path = "../src/http.rs"]
mod http;
#[path = "../src/websocket.rs"]
mod websocket;

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let app = http::router(env!("CARGO_PKG_NAME"), tokio::sync::watch::channel(false).1);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
