use std::net::SocketAddr;

use axum::{
    Router,
    routing::{get, post},
};
use db::connect_db;
use tokio::net::TcpListener;

mod auth;
mod db;
mod models;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let db = connect_db().await?;

    let app = Router::new()
        .route("/register", post(todo!()))
        .route("/login", post(todo!()))
        .route("/me", get(todo!()))
        .with_state(db);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 3000))).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
