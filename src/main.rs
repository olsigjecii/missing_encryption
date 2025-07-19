use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct User {
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (user's email)
    exp: usize,  // Expiration time
}

const SECRET_KEY: &[u8] = b"your-super-secret-and-long-key";

// Vulnerable endpoint: Generates a Base64 encoded token
async fn vulnerable_request_reset(user: web::Json<User>) -> impl Responder {
    let token = general_purpose::STANDARD.encode(&user.email);
    HttpResponse::Ok().json(serde_json::json!({ "token": token }))
}

// Vulnerable endpoint: "Resets" password with a Base64 token
async fn vulnerable_reset_password(token: web::Path<String>) -> impl Responder {
    if let Ok(email_bytes) = general_purpose::STANDARD.decode(token.into_inner()) {
        if let Ok(email) = String::from_utf8(email_bytes) {
            return HttpResponse::Ok().body(format!(
                "Password for {} has been reset (VULNERABLE)",
                email
            ));
        }
    }
    HttpResponse::BadRequest().body("Invalid token")
}

// Secure endpoint: Generates a JWT
async fn secure_request_reset(user: web::Json<User>) -> impl Responder {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user.email.clone(),
        exp: expiration as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET_KEY),
    )
    .unwrap();

    HttpResponse::Ok().json(serde_json::json!({ "token": token }))
}

// Secure endpoint: Validates the JWT and resets the password
async fn secure_reset_password(token: web::Path<String>) -> impl Responder {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    match decode::<Claims>(
        &token.into_inner(),
        &DecodingKey::from_secret(SECRET_KEY),
        &validation,
    ) {
        Ok(token_data) => HttpResponse::Ok().body(format!(
            "Password for {} has been reset (SECURE)",
            token_data.claims.sub
        )),
        Err(_) => HttpResponse::Unauthorized().body("Invalid or expired token"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load SSL keys
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();

    println!("Starting server at http://127.0.0.1:8080 and https://127.0.0.1:8443");

    HttpServer::new(|| {
        App::new()
            .service(
                web::scope("/vulnerable")
                    .route("/request-reset", web::post().to(vulnerable_request_reset))
                    .route(
                        "/reset-password/{token}",
                        web::get().to(vulnerable_reset_password),
                    ),
            )
            .service(
                web::scope("/secure")
                    .route("/request-reset", web::post().to(secure_request_reset))
                    .route(
                        "/reset-password/{token}",
                        web::get().to(secure_reset_password),
                    ),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .bind_openssl("127.0.0.1:8443", builder)?
    .run()
    .await
}
