use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const SESSION_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

pub fn create_dashboard_token(secret: &[u8], claims: Value) -> Result<String, String> {
    let issued_at = unix_time();
    let mut payload = json!({
        "authenticated": true,
        "iat": issued_at,
        "exp": issued_at + SESSION_MAX_AGE_SECONDS,
    });
    if let (Some(target), Some(claims)) = (payload.as_object_mut(), claims.as_object()) {
        target.extend(claims.clone());
    }

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let body = URL_SAFE_NO_PAD.encode(payload.to_string());
    let signed = format!("{header}.{body}");
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| "Invalid JWT secret".to_string())?;
    mac.update(signed.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{signed}.{signature}"))
}

pub fn verify_dashboard_token(secret: &[u8], token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let header_part = parts.next()?;
    let header = URL_SAFE_NO_PAD.decode(header_part).ok()?;
    let payload_part = parts.next()?;
    let signature = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&header).ok()?;
    if header.get("alg")?.as_str()? != "HS256" {
        return None;
    }
    let signed = format!("{header_part}.{payload_part}");
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(signed.as_bytes());
    mac.verify_slice(&signature).ok()?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_part).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    (payload.get("exp")?.as_u64()? > unix_time()).then_some(payload)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
