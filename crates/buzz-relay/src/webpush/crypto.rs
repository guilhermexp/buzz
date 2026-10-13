//! RFC 8291 (`aes128gcm` Web Push message encryption) and RFC 8292 (VAPID)
//! primitives. Pure functions; randomness is injected so the RFC test vectors
//! can pin the ephemeral key and salt.

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes128Gcm, KeyInit as _, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::point::AffineCoordinates as _;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha2::Sha256;

/// Record size advertised in the single-record content-coding header.
const RECORD_SIZE: u32 = 4096;
/// RFC 8291 §4: a push message is a single record of at most 4096 octets;
/// with the 86-octet header, delimiter and tag this bounds the plaintext.
pub const MAX_PLAINTEXT: usize = 3993;
/// VAPID tokens are valid for 12 hours (RFC 8292 recommends at most 24h).
const VAPID_TOKEN_SECS: i64 = 12 * 60 * 60;

/// Encrypt `plaintext` for a browser push subscription.
///
/// `ua_public` is the subscription's 65-byte uncompressed `p256dh` key,
/// `auth_secret` its 16-byte `auth` secret. `as_secret` is a fresh
/// application-server ECDH key and `salt` 16 fresh random octets.
pub fn encrypt_aes128gcm(
    plaintext: &[u8],
    ua_public: &p256::PublicKey,
    auth_secret: &[u8; 16],
    as_secret: &p256::SecretKey,
    salt: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err("push payload too large");
    }
    let ua_bytes = ua_public.to_encoded_point(false);
    let as_bytes = as_secret.public_key().to_encoded_point(false);
    let shared = (ua_public.to_projective() * *as_secret.to_nonzero_scalar()).to_affine();
    let ecdh_secret = shared.x();

    let mut key_info = Vec::with_capacity(14 + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_bytes.as_bytes());
    key_info.extend_from_slice(as_bytes.as_bytes());
    let mut ikm = [0_u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(auth_secret), &ecdh_secret)
        .expand(&key_info, &mut ikm)
        .map_err(|_| "hkdf ikm")?;

    let prk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .map_err(|_| "hkdf cek")?;
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .map_err(|_| "hkdf nonce")?;

    let mut record = Vec::with_capacity(plaintext.len() + 1);
    record.extend_from_slice(plaintext);
    // Last-record padding delimiter, no padding octets.
    record.push(0x02);
    let cipher = Aes128Gcm::new_from_slice(&cek).map_err(|_| "aes key")?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), record.as_slice())
        .map_err(|_| "aes-gcm encryption failed")?;

    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(65);
    body.extend_from_slice(as_bytes.as_bytes());
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// Encrypt with a fresh ephemeral key and salt.
pub fn encrypt_for_subscription(
    plaintext: &[u8],
    ua_public: &p256::PublicKey,
    auth_secret: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let as_secret = random_secret_key();
    let salt: [u8; 16] = rand::random();
    encrypt_aes128gcm(plaintext, ua_public, auth_secret, &as_secret, &salt)
}

fn random_secret_key() -> p256::SecretKey {
    loop {
        let candidate: [u8; 32] = rand::random();
        // A uniformly random 32-byte string is a valid scalar with
        // overwhelming probability; retry the negligible remainder.
        if let Ok(key) = p256::SecretKey::from_slice(&candidate) {
            return key;
        }
    }
}

/// VAPID application-server signing key (RFC 8292).
#[derive(Clone)]
pub struct VapidKey {
    signing: p256::ecdsa::SigningKey,
    public_b64: String,
}

impl std::fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VapidKey")
            .field("public_key", &self.public_b64)
            .finish_non_exhaustive()
    }
}

impl VapidKey {
    /// Parse a base64url-encoded raw 32-byte P-256 private scalar.
    pub fn from_base64url(raw: &str) -> Result<Self, &'static str> {
        let bytes = URL_SAFE_NO_PAD
            .decode(raw.trim().trim_end_matches('='))
            .map_err(|_| "VAPID private key must be base64url")?;
        if bytes.len() != 32 {
            return Err("VAPID private key must be a raw 32-byte P-256 scalar");
        }
        let signing = p256::ecdsa::SigningKey::from_slice(&bytes)
            .map_err(|_| "VAPID private key is not a valid P-256 scalar")?;
        let public = signing.verifying_key().to_encoded_point(false);
        Ok(Self {
            signing,
            public_b64: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        })
    }

    /// Uncompressed public key, base64url: the browser `applicationServerKey`.
    pub fn public_key_base64url(&self) -> &str {
        &self.public_b64
    }

    /// `Authorization` header value for one push-service origin.
    pub fn authorization(&self, audience: &str, subject: &str, now: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = serde_json::json!({
            "aud": audience,
            "exp": now + VAPID_TOKEN_SECS,
            "sub": subject,
        });
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header}.{claims}");
        let signature: p256::ecdsa::Signature = self.signing.sign(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("vapid t={signing_input}.{signature}, k={}", self.public_b64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;

    fn b64(value: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(value).unwrap()
    }

    // RFC 8291 §5 / Appendix A.
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AS_PUBLIC: &str =
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

    fn vector_inputs() -> (p256::PublicKey, [u8; 16], p256::SecretKey, [u8; 16]) {
        let ua_public = p256::PublicKey::from_sec1_bytes(&b64(UA_PUBLIC)).unwrap();
        let auth: [u8; 16] = b64(AUTH).try_into().unwrap();
        let as_secret = p256::SecretKey::from_slice(&b64(AS_PRIVATE)).unwrap();
        let salt: [u8; 16] = b64(SALT).try_into().unwrap();
        (ua_public, auth, as_secret, salt)
    }

    #[test]
    fn rfc8291_example_body_is_reproduced_exactly() {
        let (ua_public, auth, as_secret, salt) = vector_inputs();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(as_secret.public_key().to_encoded_point(false).as_bytes()),
            AS_PUBLIC
        );
        let body = encrypt_aes128gcm(
            b"When I grow up, I want to be a watermelon",
            &ua_public,
            &auth,
            &as_secret,
            &salt,
        )
        .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&body), BODY);
    }

    #[test]
    fn receiver_derives_the_same_ecdh_secret() {
        // Appendix A: ecdh_secret is symmetric between UA and application server.
        let (ua_public, _, as_secret, _) = vector_inputs();
        let ua_secret = p256::SecretKey::from_slice(&b64(UA_PRIVATE)).unwrap();
        let sender = (ua_public.to_projective() * *as_secret.to_nonzero_scalar()).to_affine();
        let receiver =
            (as_secret.public_key().to_projective() * *ua_secret.to_nonzero_scalar()).to_affine();
        assert_eq!(sender.x(), receiver.x());
        assert_eq!(
            URL_SAFE_NO_PAD.encode(sender.x()),
            "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs"
        );
    }

    #[test]
    fn fresh_encryption_uses_unique_salt_and_key_and_bounds_size() {
        let (ua_public, auth, _, _) = vector_inputs();
        let first = encrypt_for_subscription(b"{}", &ua_public, &auth).unwrap();
        let second = encrypt_for_subscription(b"{}", &ua_public, &auth).unwrap();
        assert_ne!(first[..16], second[..16]);
        assert_ne!(first[21..86], second[21..86]);
        // header 86 + plaintext 2 + delimiter 1 + tag 16
        assert_eq!(first.len(), 86 + 2 + 1 + 16);
        assert!(
            encrypt_for_subscription(&vec![b'x'; MAX_PLAINTEXT + 1], &ua_public, &auth).is_err()
        );
    }

    #[test]
    fn vapid_authorization_is_a_verifiable_es256_jwt() {
        let key = VapidKey::from_base64url(AS_PRIVATE).unwrap();
        assert_eq!(key.public_key_base64url(), AS_PUBLIC);
        let header = key.authorization("https://push.example", "mailto:ops@example.com", 1_000);
        let rest = header.strip_prefix("vapid t=").unwrap();
        let (token, k) = rest.split_once(", k=").unwrap();
        assert_eq!(k, AS_PUBLIC);
        let mut parts = token.split('.');
        let (h, c, s) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let claims: serde_json::Value = serde_json::from_slice(&b64(c)).unwrap();
        assert_eq!(claims["aud"], "https://push.example");
        assert_eq!(claims["sub"], "mailto:ops@example.com");
        assert_eq!(claims["exp"], 1_000 + VAPID_TOKEN_SECS);
        let header_json: serde_json::Value = serde_json::from_slice(&b64(h)).unwrap();
        assert_eq!(header_json["alg"], "ES256");
        let signature = p256::ecdsa::Signature::from_slice(&b64(s)).unwrap();
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&b64(AS_PUBLIC)).unwrap();
        verifying
            .verify(format!("{h}.{c}").as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn vapid_key_rejects_wrong_lengths_and_invalid_scalars() {
        assert!(VapidKey::from_base64url("AAAA").is_err());
        assert!(VapidKey::from_base64url(&URL_SAFE_NO_PAD.encode([0_u8; 32])).is_err());
        assert!(VapidKey::from_base64url("not base64!").is_err());
    }
}
