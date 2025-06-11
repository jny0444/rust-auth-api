use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use std::env;

pub type Db = Pool<Postgres>;

pub async fn connect_db() -> Result<Db, sqlx::Error> {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    Ok(pool)
}
