# Snyk Learn Lesson on Missing Encryption 🦀

## Lesson Summary

This lesson explores the critical security vulnerability known as **Missing Encryption of Sensitive Data**. We demonstrate how easily data can be compromised when it is merely encoded rather than properly encrypted or signed. The core of this lesson is to understand that encoding, such as Base64, is not a form of security. It is easily reversible and provides no protection against data tampering.

In our demonstration, we examine a flawed password reset mechanism.

- **The Vulnerability**: A password reset token is created by simply Base64 encoding a user's email address. At first glance, this token may look like a random string of text, but it is predictable and can be easily decoded. An attacker can decode this token, replace the email with another user's email (e.g., an admin), re-encode it, and use the new malicious token to take over that user's account.
- **The Mitigation**: To fix this, we must ensure the integrity of the data within the token. The solution is to use a strong cryptographic signature. We implement this using JSON Web Tokens (JWT) signed with an HS256 (HMAC with SHA256) algorithm. The server uses a secret key to sign the token's data. If an attacker modifies the data, the signature will no longer be valid, and the server will reject the token, preventing the account takeover.

## Demonstration Application Setup

Follow these steps to set up and run the demonstration application.

### 1. Prerequisites

- Ensure you have Rust and Cargo installed. If not, visit [rust-lang.org](https://www.rust-lang.org/tools/install).
- Ensure you have `openssl` available in your command line for generating a self-signed certificate.

### 2. Clone the Repository

```bash
git clone <repo-url>
```

### 3. Generate a Self-Signed SSL Certificate

For our secure (HTTPS) endpoint, we need an SSL certificate. Run the following command in the root of your project directory:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

This will create two files: `key.pem` (the private key) and `cert.pem` (the certificate).

### 4. Run the Application

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

This demonstrates that by signing the token, we have protected its integrity and mitigated the vulnerability.
