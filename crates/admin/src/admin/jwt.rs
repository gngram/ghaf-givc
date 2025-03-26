use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct VMInfo {
    id: String,
    name: String,
    ip: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
    purpose: String,  // Purpose of communication
    src_vm: VMInfo,   // Source VM details
    dst_vm: VMInfo,   // Destination VM details
    iat: usize,       // Issued at (UNIX timestamp)
    exp: usize,       // Expiration time
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    token: String,     // The signed JWT
    claims: TokenClaims, // The decoded claims for reference
}

fn generate_token_json(secret: &str, purpose: &str, src: VMInfo, dst: VMInfo) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = TokenClaims {
        purpose: purpose.to_string(),
        src_vm: src,
        dst_vm: dst,
        iat: now,
        exp: now + 300,  // Expires in 5 minutes
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).unwrap();

    let response = TokenResponse { token, claims };

    serde_json::to_string_pretty(&response).unwrap()
}

fn main() {
    let secret = "secure_secret_key";

    let src_vm = VMInfo {
        id: "vm-1".to_string(),
        name: "source-vm".to_string(),
        ip: "192.168.1.10".to_string(),
    };

    let dst_vm = VMInfo {
        id: "vm-2".to_string(),
        name: "destination-vm".to_string(),
        ip: "192.168.1.20".to_string(),
    };

    let json_response = generate_token_json(secret, "data-transfer", src_vm, dst_vm);
    println!("{}", json_response);
}
