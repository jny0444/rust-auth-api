use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use axum::{
    Json,
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
};
use uuid::Uuid;

use crate::{
    auth::{generate_jwt, verify_jwt},
    db::Db,
    models::{LoginPayload, RegisterPayload, User, UserResponse},
};

/*
pub async fn register(
    State(db): State<Db>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Json<UserResponse>, StatusCode> {
    let salt = SaltString::generate(&mut OsRng);

    let mut hashed_output = [0u8; 32];

    Argon2::default()
        .hash_password_into(
            payload.password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut hashed_output,
        )
        .unwrap();
    let hash_str = hex::encode(hashed_output);

    let user_uuid = Uuid::new_v4();

    let user = sqlx::query_as!(
    User,
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, password_hash",
        user_uuid,
        payload.email,
        hash_str,
    ).fetch_one(&db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
    }))
}
*/

pub async fn register(
    State(db): State<Db>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Json<UserResponse>, StatusCode> {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash_str = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| {
            eprintln!("Failed to hash password: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_string();

    let user_uuid = Uuid::new_v4();

    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, password_hash",
        user_uuid,
        payload.email,
        password_hash_str,
    )
    .fetch_one(&db)
    .await
    .map_err(|e| {
        eprintln!("Failed to insert user into database: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
    }))
}

pub async fn login(
    State(db): State<Db>,
    Json(payload): Json<LoginPayload>,
) -> Result<String, StatusCode> {
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, password_hash FROM users WHERE email = $1",
        payload.email,
    )
    .fetch_optional(&db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    println!("done db query");

    let parsed_hash =
        PasswordHash::new(&user.password_hash).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    println!("password hash");

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token = generate_jwt(&user.email).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    println!("Generated token: {}", token);

    Ok(token)
}

pub async fn me(req: Request) -> Result<Json<String>, StatusCode> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = verify_jwt(token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(claims.sub))
}
