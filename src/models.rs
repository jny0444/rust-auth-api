use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize, FromRow)]
pub struct UserWithHash {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
}
