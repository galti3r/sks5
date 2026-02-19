use axum::{http::StatusCode, response::IntoResponse};

pub async fn serve_dashboard() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "text/html; charset=utf-8"),
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self' 'sha256-wCmXlMHpIClYkYq0aXm9uw+lJl/ZvEYJJLkwrIsRgrs='; style-src 'self' 'sha256-ZKm9QsynWZJOuWIguTSYf4VV/zPNgfaY7hTtPyr7qls='; connect-src 'self' ws: wss:",
            ),
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
        ],
        include_str!("../../assets/dashboard.html"),
    )
}
