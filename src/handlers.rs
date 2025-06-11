use argon2::{
    Argon2, Error, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::{env, str::from_utf8};
use uuid::Uuid;

use crate::models::{LoginPayload, RegisterPayload, User, UserWithHash};

pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let mut hash_buf = [0u8; 128];

    Argon2::default().hash_password_into(
        password.as_bytes(),
        salt.as_str().as_bytes(),
        &mut hash_buf,
    )?;

    let len = hash_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(hash_buf.len());

    Ok(from_utf8(&hash_buf[..len]).unwrap().to_string())
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub async fn register(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterPayload>,
) -> impl IntoResponse {
    let hashed = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response();
        }
    };

    let user = match sqlx::query_as!(
        User,
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email",
        Uuid::new_v4(),
        payload.email,
        hashed
    )
    .fetch_one(&pool)
    .await
    {
        Ok(user) => user,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(),
    };

    (StatusCode::CREATED, Json(user)).into_response()
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(payload): Json<LoginPayload>,
) -> impl IntoResponse {
    let row = sqlx::query_as!(
        UserWithHash,
        "SELECT id, email, password_hash FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&pool)
    .await;

    let user = match row {
        Ok(Some(u)) => u,
        _ => return (StatusCode::UNAUTHORIZED, "Invalid Credentials").into_response(),
    };

    if !argon2::Argon2::default()
        .verify_password(
            payload.password.as_bytes(),
            &argon2::PasswordHash::new(&user.password_hash).unwrap(),
        )
        .is_ok()
    {
        return (StatusCode::UNAUTHORIZED, "Invalid Credentials").into_response();
    }

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");
    let exp = (Utc::now() + Duration::hours(24)).timestamp() as usize;
    let claims = Claims {
        sub: user.id.to_string(),
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap();

    (StatusCode::OK, Json(json!({"token": token}))).into_response()
}

pub async fn me(headers: HeaderMap) -> impl IntoResponse {
    let auth = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(|s| s.to_string()));

    let token = match auth {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");

    let data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    );

    match data {
        Ok(claims) => (
            StatusCode::OK,
            Json(json!({ "user_id": claims.claims.sub })),
        )
            .into_response(),
        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    }
}
