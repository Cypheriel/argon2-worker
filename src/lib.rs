use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{routing::get, Json, Router};
use serde_json::json;
use std::collections::HashMap;
use tower_service::Service;
use urlencoding::encode;
use worker::{Context, Env, HttpRequest};
use worker_macros::event;

// --- /hash structs
#[derive(Debug)]
pub enum HashError {
    MissingValue,
    Argon2Failure,
}

impl IntoResponse for HashError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            HashError::MissingValue => (StatusCode::BAD_REQUEST, "Missing parameter: value"),
            HashError::Argon2Failure => (StatusCode::INTERNAL_SERVER_ERROR, "Argon2 failure"),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

// --- /verify structs
#[derive(Debug)]
pub enum VerifyError {
    MissingValue,
    Argon2Failure,
    VerifyFailure,
}

impl IntoResponse for VerifyError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            VerifyError::MissingValue => (
                StatusCode::BAD_REQUEST,
                "Missing parameter(s): value OR salt",
            ),
            VerifyError::Argon2Failure => (StatusCode::INTERNAL_SERVER_ERROR, "Argon2 failure"),
            VerifyError::VerifyFailure => (StatusCode::BAD_REQUEST, "Verification failure"),
        };

        let body = Json(json!({
            "status": "error",
            "message": error_message,
        }));

        (status, body).into_response()
    }
}

// --- Router

fn router() -> Router {
    Router::new()
        .route("/hash", get(hash_handler))
        .route("/verify", get(verify_handler))
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> worker::Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    Ok(router().call(req).await?)
}

// --- Handlers

// -- /hash
pub async fn hash_handler(
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, HashError> {
    let argon2 = Argon2::default();

    let Some(value) = params.get("value") else {
        return Err(HashError::MissingValue);
    };
    let url_encode = params.get("urlencode").is_some();

    let salt = SaltString::generate(&mut OsRng);
    let Ok(hash) = argon2.hash_password(value.as_ref(), &salt) else {
        return Err(HashError::Argon2Failure);
    };

    let mut result_hash = hash.to_string();
    if url_encode {
        result_hash = encode(&*result_hash).to_string();
    }

    Ok(result_hash)
}

// -- /verify
pub async fn verify_handler(
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, VerifyError> {
    let argon2 = Argon2::default();
    let Some(value) = params.get("value") else {
        return Err(VerifyError::MissingValue);
    };
    let Some(hash) = params.get("hash") else {
        return Err(VerifyError::MissingValue);
    };

    let password_hash = PasswordHash::new(&hash).map_err(|_| VerifyError::Argon2Failure)?;

    if argon2
        .verify_password(value.as_ref(), &password_hash)
        .is_err()
    {
        return Err(VerifyError::VerifyFailure);
    }

    Ok(Json(
        json!({"status": "ok", "message": "Successfully verified"}),
    ))
}
