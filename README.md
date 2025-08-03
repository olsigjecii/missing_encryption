# Snyk Learn Lesson on Missing Encryption 🦀

## Lesson Summary

[cite\_start]This lesson explores the critical security vulnerability known as **Missing Encryption of Sensitive Data**[cite: 13]. We demonstrate how easily data can be compromised when it is merely encoded rather than properly encrypted or signed. The core of this lesson is to understand that encoding, such as Base64, is not a form of security. [cite\_start]It is easily reversible and provides no protection against data tampering[cite: 87, 88].

In our demonstration, we examine a flawed password reset mechanism.

  * **The Vulnerability**: A password reset token is created by simply Base64 encoding a user's email address. [cite\_start]At first glance, this token may look like a random string of text, but it is predictable and can be easily decoded[cite: 88]. [cite\_start]An attacker can decode this token, replace the email with another user's email (e.g., an admin), re-encode it, and use the new malicious token to take over that user's account[cite: 89, 94].
  * **The Mitigation**: To fix this, we must ensure the integrity of the data within the token. [cite\_start]The solution is to use a strong cryptographic signature[cite: 96, 98]. [cite\_start]We implement this using JSON Web Tokens (JWT) signed with an HS256 (HMAC with SHA256) algorithm[cite: 100]. The server uses a secret key to sign the token's data. [cite\_start]If an attacker modifies the data, the signature will no longer be valid, and the server will reject the token, preventing the account takeover[cite: 101, 166].

## Demonstration Application Setup

Follow these steps to set up and run the demonstration application.

### 1\. Prerequisites

  * Ensure you have Rust and Cargo installed. If not, visit [rust-lang.org](https://www.rust-lang.org/tools/install).
  * Ensure you have `openssl` available in your command line for generating a self-signed certificate.

### 2\. Create the Rust Project

```bash
cargo new rust_missing_encryption
cd rust_missing_encryption
```

### 3\. Configure Dependencies

Open the `Cargo.toml` file and add the following dependencies:

```toml
[dependencies]
actix-web = { version = "4", features = ["openssl"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22.1"
jsonwebtoken = "9.3.0"
openssl = { version = "0.10", features = ["v110"] }
chrono = { version = "0.4", features = ["serde"] }
```

### 4\. Generate a Self-Signed SSL Certificate

For our secure (HTTPS) endpoint, we need an SSL certificate. Run the following command in the root of your project directory:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

This will create two files: `key.pem` (the private key) and `cert.pem` (the certificate).

### 5\. Create the Application Code

Create a file at `src/main.rs` and add the following Rust code:

```rust
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use chrono::Utc;

#[derive(Debug, Serialize, Deserialize)]
struct User {
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (user's email)
    exp: i64,  // Expiration time
}

// IMPORTANT: In a real application, load this from a secure configuration!
const SECRET_KEY: &[u8] = b"your-super-secret-and-long-key-that-is-at-least-32-bytes";

// --- VULNERABLE IMPLEMENTATION ---

async fn vulnerable_request_reset(user: web::Json<User>) -> impl Responder {
    let token = general_purpose::STANDARD.encode(&user.email);
    HttpResponse::Ok().json(serde_json::json!({ "token": token }))
}

async fn vulnerable_reset_password(token: web::Path<String>) -> impl Responder {
    if let Ok(email_bytes) = general_purpose::STANDARD.decode(token.into_inner()) {
        if let Ok(email) = String::from_utf8(email_bytes) {
            return HttpResponse::Ok().body(format!("[VULNERABLE] Password for {} has been reset.", email));
        }
    }
    HttpResponse::BadRequest().body("Invalid token")
}

// --- SECURE IMPLEMENTATION ---

async fn secure_request_reset(user: web::Json<User>) -> impl Responder {
    let expiration = (Utc::now() + chrono::Duration::hours(1)).timestamp();
    let claims = Claims {
        sub: user.email.clone(),
        exp: expiration,
    };

    let token = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(SECRET_KEY))
        .unwrap();

    HttpResponse::Ok().json(serde_json::json!({ "token": token }))
}

async fn secure_reset_password(token: web::Path<String>) -> impl Responder {
    let validation = Validation::new(Algorithm::HS256);
    match decode::<Claims>(&token.into_inner(), &DecodingKey::from_secret(SECRET_KEY), &validation) {
        Ok(token_data) => {
            HttpResponse::Ok().body(format!("[SECURE] Password for {} has been reset.", token_data.claims.sub))
        }
        Err(_) => HttpResponse::Unauthorized().body("Invalid or expired token. Tampering detected."),
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

    println!("Server running...");
    println!("Vulnerable endpoints available at http://127.0.0.1:8080");
    println!("Secure endpoints available at https://127.0.0.1:8443");

    HttpServer::new(|| {
        App::new()
            .service(
                web::scope("/vulnerable")
                    .route("/request-reset", web::post().to(vulnerable_request_reset))
                    .route("/reset-password/{token}", web::get().to(vulnerable_reset_password))
            )
            .service(
                web::scope("/secure")
                    .route("/request-reset", web::post().to(secure_request_reset))
                    .route("/reset-password/{token}", web::get().to(secure_reset_password))
            )
    })
    .bind(("127.0.0.1", 8080))?
    .bind_openssl("127.0.0.1:8443", builder)?
    .run()
    .await
}
```

### 6\. Run the Application

From the root of your project directory, run:

```bash
cargo run
```

## Vulnerability Demonstration

We will now exploit the vulnerable endpoint to take over another user's account.

#### Step 1: Request a password reset token for a regular user.

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"email": "lily@example.com"}' \
  http://127.0.0.1:8080/vulnerable/request-reset
```

The server responds with a Base64 encoded token:
`{"token":"bGlseUBlLmV4YW1wbGUuY29t"}`

#### Step 2: As an attacker, decode the token to reveal its contents.

```bash
echo "bGlseUBlLmV4YW1wbGUuY29t" | base64 --decode
# Output: lily@example.com
```

#### Step 3: Create a malicious token for the admin user.

The attacker now encodes the admin's email address to generate a new token.

```bash
echo -n "admin@example.com" | base64
# Output: YWRtaW5AZXhhbXBsZS5jb20=
```

#### Step 4: Use the malicious token to reset the admin's password.

The attacker uses the forged token to call the reset endpoint.

```bash
curl http://127.0.0.1:8080/vulnerable/reset-password/YWRtaW5AZXhhbXBsZS5jb20=
```

The server, having no way to validate the token's integrity, happily resets the admin's password:
`[VULNERABLE] Password for admin@example.com has been reset.`

**The account is now compromised.**

## Mitigation Demonstration

Now, we will show how the secure, JWT-based implementation prevents this attack.

#### Step 1: Request a secure token.

Note that we use the `https` endpoint. The `-k` flag is used to trust our self-signed certificate.

```bash
curl -k -X POST -H "Content-Type: application/json" \
  -d '{"email": "lily@example.com"}' \
  https://127.0.0.1:8443/secure/request-reset
```

The server responds with a signed JWT. It is much longer because it contains a header, the data (payload), and a cryptographic signature.
`{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsaWx5QGV4YW1wbGUuY29tIiwiZXhwIjoxNzUyMjk5MDM3fQ.r_FLA_t1yB6p..."}`

#### Step 2: Attempt to use a forged token.

If the attacker tries the same trick of creating a simple Base64 token for the admin user and sends it to the secure endpoint, the server will reject it.

```bash
# Using the old malicious token from the vulnerable example
curl -k https://127.0.0.1:8443/secure/reset-password/YWRtaW5AZXhhbXBsZS5jb20=
```

The server rejects the token because it is not a valid JWT and fails the signature check:
`Invalid or expired token. Tampering detected.`

#### Step 3: Use the legitimate token.

Using the original, untampered JWT works as expected.

```bash
# Use the actual token you received in Step 1
curl -k https://127.0.0.1:8443/secure/reset-password/eyJ0eX...<rest_of_your_token>...
```

The server successfully validates the JWT signature and allows the password reset:
`[SECURE] Password for lily@example.com has been reset.`

[cite\_start]This demonstrates that by signing the token, we have protected its integrity and mitigated the vulnerability[cite: 166].