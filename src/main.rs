use std::net::SocketAddr;

use axum::{
    Router,
    routing::{get, post},
};
use db::connect_db;
use dotenvy::dotenv;
use handlers::{login, me, register};
use tokio::net::TcpListener;

mod db;
mod handlers;
mod models;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    dotenv().ok();

    let db = connect_db().await?;

    let app = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/me", get(me))
        .with_state(db);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 3000))).await?;

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
