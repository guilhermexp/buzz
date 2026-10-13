//! NIP-PL `webpush` transport: browser Push API subscriptions delivered
//! directly by the relay (RFC 8030 + RFC 8291 + RFC 8292).
//!
//! The stored endpoint grant of a `webpush` lease is the canonical JSON of the
//! browser subscription `{"endpoint","keys":{"p256dh","auth"}}`. Endpoint URLs
//! are restricted to HTTPS hosts on an operator allow-list of real push
//! services so a lease cannot turn the relay into an SSRF client.

pub mod crypto;

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub use crypto::VapidKey;

/// NIP-PL transport identifier.
pub const TRANSPORT: &str = "webpush";

/// Default push services (Mozilla autopush, Google FCM, Apple, Microsoft WNS).
/// A leading dot allows any subdomain.
pub const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    "updates.push.services.mozilla.com",
    "fcm.googleapis.com",
    "web.push.apple.com",
    ".notify.windows.com",
];

/// Hard timeout for one push-service request (internet round trip).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Operator configuration for relay-originated Web Push delivery.
#[derive(Debug, Clone)]
pub struct WebPushConfig {
    /// RFC 8292 application-server signing key.
    pub vapid: VapidKey,
    /// VAPID `sub` claim: operator contact (`mailto:` or `https:`).
    pub subject: String,
    /// Push-service hosts endpoints may target; `.suffix` allows subdomains.
    pub allowed_hosts: Vec<String>,
}

impl WebPushConfig {
    /// Read `BUZZ_PUSH_VAPID_PRIVATE_KEY`, `BUZZ_PUSH_VAPID_SUBJECT` and
    /// `BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS`. Absent key → transport disabled.
    pub fn from_env() -> Result<Option<Self>, String> {
        let key = match std::env::var("BUZZ_PUSH_VAPID_PRIVATE_KEY") {
            Ok(raw) if raw.trim().is_empty() => return Ok(None),
            Ok(raw) => VapidKey::from_base64url(&raw)
                .map_err(|e| format!("BUZZ_PUSH_VAPID_PRIVATE_KEY: {e}"))?,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err("BUZZ_PUSH_VAPID_PRIVATE_KEY must be valid UTF-8".to_string()),
        };
        let subject = std::env::var("BUZZ_PUSH_VAPID_SUBJECT").map_err(|_| {
            "BUZZ_PUSH_VAPID_SUBJECT must be configured with BUZZ_PUSH_VAPID_PRIVATE_KEY"
                .to_string()
        })?;
        let subject = parse_subject(&subject)?;
        let allowed_hosts = match std::env::var("BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS") {
            Ok(raw) => parse_allowed_hosts(&raw)?,
            Err(_) => DEFAULT_ALLOWED_HOSTS
                .iter()
                .map(|h| (*h).to_string())
                .collect(),
        };
        Ok(Some(Self {
            vapid: key,
            subject,
            allowed_hosts,
        }))
    }
}

fn parse_subject(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let valid = match raw.strip_prefix("mailto:") {
        Some(address) => {
            address.contains('@') && !address.contains(char::is_whitespace) && address.len() > 2
        }
        None => {
            url::Url::parse(raw).is_ok_and(|url| url.scheme() == "https" && url.host().is_some())
        }
    };
    if !valid || raw.len() > 256 {
        return Err("BUZZ_PUSH_VAPID_SUBJECT must be a mailto: address or https: URL".to_string());
    }
    Ok(raw.to_string())
}

fn parse_allowed_hosts(raw: &str) -> Result<Vec<String>, String> {
    let hosts: Vec<String> = raw
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    let valid_label = |host: &str| {
        let bare = host.strip_prefix('.').unwrap_or(host);
        bare.contains('.')
            && bare.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            && bare.parse::<std::net::IpAddr>().is_err()
    };
    if hosts.is_empty() || !hosts.iter().all(|h| valid_label(h)) {
        return Err(
            "BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS must list DNS push-service hosts (\".suffix\" allows subdomains)"
                .to_string(),
        );
    }
    Ok(hosts)
}

fn host_allowed(host: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|entry| match entry.strip_prefix('.') {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.')),
        None => host == entry,
    })
}

/// Browser `PushSubscription` JSON as carried in a NIP-PL `webpush` lease.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionJson {
    /// Push-service URL the browser issued for this subscription.
    pub endpoint: String,
    /// Browser encryption keys.
    pub keys: SubscriptionKeys,
}

/// `PushSubscription.keys`, base64url without padding.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionKeys {
    /// User-agent ECDH public key (uncompressed P-256 point).
    pub p256dh: String,
    /// 16-octet authentication secret.
    pub auth: String,
}

/// A validated, deliverable Web Push subscription.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Validated HTTPS push-service endpoint on the allow-list.
    pub endpoint: url::Url,
    /// User-agent ECDH public key, validated on-curve.
    pub ua_public: p256::PublicKey,
    /// User-agent authentication secret.
    pub auth_secret: [u8; 16],
    /// Canonical JSON stored as the lease endpoint grant.
    pub canonical: String,
}

impl Subscription {
    /// RFC 8292 `aud`: the push-service origin.
    pub fn audience(&self) -> String {
        self.endpoint.origin().ascii_serialization()
    }
}

/// Whether a stored endpoint grant belongs to the `webpush` transport.
/// Other transports' grants are opaque tokens that never start with `{`
/// (lease acceptance enforces this), so the stored form is unambiguous.
pub fn is_webpush_grant(grant: &str) -> bool {
    grant.starts_with('{')
}

/// Parse and validate a lease endpoint against the push-service allow-list.
pub fn parse_subscription(raw: &str, allowed_hosts: &[String]) -> Result<Subscription, String> {
    let json: SubscriptionJson =
        serde_json::from_str(raw).map_err(|_| "invalid webpush subscription".to_string())?;
    let endpoint =
        url::Url::parse(&json.endpoint).map_err(|_| "invalid webpush endpoint URL".to_string())?;
    let host = match endpoint.host() {
        Some(url::Host::Domain(host)) => host.to_ascii_lowercase(),
        _ => return Err("webpush endpoint must use a DNS host".to_string()),
    };
    if endpoint.scheme() != "https"
        || endpoint.port().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("webpush endpoint must be a plain https URL".to_string());
    }
    if !host_allowed(&host, allowed_hosts) {
        return Err("webpush endpoint host is not an allowed push service".to_string());
    }
    let p256dh = URL_SAFE_NO_PAD
        .decode(json.keys.p256dh.trim_end_matches('='))
        .map_err(|_| "invalid webpush p256dh".to_string())?;
    if p256dh.len() != 65 || p256dh[0] != 0x04 {
        return Err("webpush p256dh must be an uncompressed P-256 point".to_string());
    }
    // `from_sec1_bytes` rejects points that are not on the curve (RFC 8291 §7).
    let ua_public = p256::PublicKey::from_sec1_bytes(&p256dh)
        .map_err(|_| "webpush p256dh is not a valid P-256 point".to_string())?;
    let auth_secret: [u8; 16] = URL_SAFE_NO_PAD
        .decode(json.keys.auth.trim_end_matches('='))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "webpush auth must be 16 octets".to_string())?;
    let canonical = serde_json::to_string(&SubscriptionJson {
        endpoint: endpoint.as_str().to_string(),
        keys: SubscriptionKeys {
            p256dh: URL_SAFE_NO_PAD.encode(&p256dh),
            auth: URL_SAFE_NO_PAD.encode(auth_secret),
        },
    })
    .map_err(|_| "invalid webpush subscription".to_string())?;
    Ok(Subscription {
        endpoint,
        ua_public,
        auth_secret,
        canonical,
    })
}

/// The encrypted notification payload. Carries routing identifiers only —
/// never message content; the client re-reads the event under its own
/// authorization when the notification is opened.
#[derive(Debug, Serialize)]
pub struct Payload<'a> {
    /// Payload schema version.
    pub v: u8,
    /// NIP-PL descriptor origin of the community.
    pub origin: &'a str,
    /// Channel the event belongs to, when channel-scoped.
    pub channel: Option<String>,
    /// Event id (hex) that caused the wake.
    pub event: String,
    /// Event kind, when the event could be loaded.
    pub kind: Option<u16>,
}

/// Outcome of one push-service request, mapped by the caller onto the
/// existing outbox semantics.
#[derive(Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// 2xx: the push service accepted the message.
    Accepted,
    /// 404/410: the subscription no longer exists.
    EndpointGone,
    /// 429/5xx/network: retry, optionally after the advertised delay.
    Retry(Option<i64>),
    /// Any other status: terminal failure for this wake.
    Failed(u16),
}

/// RFC 8030 `Urgency` for a NIP-PL wake class.
fn urgency(class: &str) -> &'static str {
    match class {
        "silent" => "very-low",
        "time_sensitive" | "urgent" => "high",
        _ => "normal",
    }
}

/// HTTP client for push services: no redirects (the allow-list applies to
/// the exact endpoint) and an internet-scale timeout.
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Build the encrypted, VAPID-signed request for one wake.
pub fn build_request(
    http: &reqwest::Client,
    config: &WebPushConfig,
    subscription: &Subscription,
    payload: &[u8],
    class: &str,
    ttl_secs: i64,
    now: i64,
) -> Result<reqwest::RequestBuilder, &'static str> {
    let body = crypto::encrypt_for_subscription(
        payload,
        &subscription.ua_public,
        &subscription.auth_secret,
    )?;
    let authorization = config
        .vapid
        .authorization(&subscription.audience(), &config.subject, now);
    Ok(http
        .post(subscription.endpoint.clone())
        .header("Authorization", authorization)
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("TTL", ttl_secs.max(0).to_string())
        .header("Urgency", urgency(class))
        .body(body))
}

/// Map a push-service response (RFC 8030 §5, §8.3).
pub fn classify_response(
    status: reqwest::StatusCode,
    retry_after: Option<&str>,
) -> DeliveryOutcome {
    use reqwest::StatusCode;
    if status.is_success() {
        return DeliveryOutcome::Accepted;
    }
    match status {
        StatusCode::NOT_FOUND | StatusCode::GONE => DeliveryOutcome::EndpointGone,
        StatusCode::TOO_MANY_REQUESTS => DeliveryOutcome::Retry(parse_retry_after(retry_after)),
        s if s.is_server_error() => DeliveryOutcome::Retry(parse_retry_after(retry_after)),
        s => DeliveryOutcome::Failed(s.as_u16()),
    }
}

fn parse_retry_after(raw: Option<&str>) -> Option<i64> {
    raw.and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|secs| (1..=3600).contains(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";

    fn allowed() -> Vec<String> {
        DEFAULT_ALLOWED_HOSTS
            .iter()
            .map(|h| (*h).to_string())
            .collect()
    }

    fn sub(endpoint: &str) -> String {
        serde_json::json!({"endpoint": endpoint, "keys": {"p256dh": UA_PUBLIC, "auth": AUTH}})
            .to_string()
    }

    #[test]
    fn accepts_real_push_services_and_canonicalizes() {
        let parsed = parse_subscription(
            &sub("https://updates.push.services.mozilla.com/wpush/v2/gAAAA"),
            &allowed(),
        )
        .unwrap();
        assert_eq!(
            parsed.audience(),
            "https://updates.push.services.mozilla.com"
        );
        assert!(is_webpush_grant(&parsed.canonical));
        let reparsed = parse_subscription(&parsed.canonical, &allowed()).unwrap();
        assert_eq!(reparsed.canonical, parsed.canonical);
        assert!(
            parse_subscription(&sub("https://fcm.googleapis.com/fcm/send/abc"), &allowed()).is_ok()
        );
        assert!(parse_subscription(
            &sub("https://wns2-par02p.notify.windows.com/w/?token=x"),
            &allowed()
        )
        .is_ok());
    }

    #[test]
    fn rejects_ssrf_shaped_endpoints() {
        for endpoint in [
            "http://updates.push.services.mozilla.com/wpush/v2/x",
            "https://127.0.0.1/wpush",
            "https://[::1]/wpush",
            "https://localhost/wpush",
            "https://updates.push.services.mozilla.com:8443/x",
            "https://user@fcm.googleapis.com/x",
            "https://fcm.googleapis.com.evil.example/x",
            "https://evilfcm.googleapis.com/x",
            "https://notify.windows.com/x",
            "https://xnotify.windows.com/x",
            "https://fcm.googleapis.com/x#frag",
        ] {
            assert!(
                parse_subscription(&sub(endpoint), &allowed()).is_err(),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn rejects_invalid_keys_and_unknown_fields() {
        let endpoint = "https://fcm.googleapis.com/fcm/send/abc";
        let bad_point = serde_json::json!({"endpoint": endpoint, "keys": {"p256dh": URL_SAFE_NO_PAD.encode([4_u8; 65]), "auth": AUTH}});
        assert!(parse_subscription(&bad_point.to_string(), &allowed()).is_err());
        let short_auth = serde_json::json!({"endpoint": endpoint, "keys": {"p256dh": UA_PUBLIC, "auth": "AAAA"}});
        assert!(parse_subscription(&short_auth.to_string(), &allowed()).is_err());
        let extra = serde_json::json!({"endpoint": endpoint, "expirationTime": null, "keys": {"p256dh": UA_PUBLIC, "auth": AUTH}});
        assert!(parse_subscription(&extra.to_string(), &allowed()).is_err());
        assert!(parse_subscription("opaque-apns-grant", &allowed()).is_err());
        assert!(!is_webpush_grant("opaque-apns-grant"));
    }

    #[test]
    fn allow_list_and_subject_configuration_are_strict() {
        assert_eq!(
            parse_allowed_hosts(" FCM.googleapis.com , .notify.windows.com ").unwrap(),
            vec!["fcm.googleapis.com", ".notify.windows.com"]
        );
        for invalid in [
            "",
            "localhost",
            "127.0.0.1",
            "https://fcm.googleapis.com",
            "a..b",
        ] {
            assert!(parse_allowed_hosts(invalid).is_err(), "{invalid}");
        }
        assert!(parse_subject("mailto:ops@example.com").is_ok());
        assert!(parse_subject("https://buzz.example").is_ok());
        assert!(parse_subject("http://buzz.example").is_err());
        assert!(parse_subject("ops@example.com").is_err());
    }

    #[test]
    fn response_mapping_follows_rfc8030() {
        use reqwest::StatusCode;
        assert_eq!(
            classify_response(StatusCode::CREATED, None),
            DeliveryOutcome::Accepted
        );
        assert_eq!(
            classify_response(StatusCode::GONE, None),
            DeliveryOutcome::EndpointGone
        );
        assert_eq!(
            classify_response(StatusCode::NOT_FOUND, None),
            DeliveryOutcome::EndpointGone
        );
        assert_eq!(
            classify_response(StatusCode::TOO_MANY_REQUESTS, Some("30")),
            DeliveryOutcome::Retry(Some(30))
        );
        assert_eq!(
            classify_response(
                StatusCode::SERVICE_UNAVAILABLE,
                Some("Wed, 21 Oct 2015 07:28:00 GMT")
            ),
            DeliveryOutcome::Retry(None)
        );
        assert_eq!(
            classify_response(StatusCode::PAYLOAD_TOO_LARGE, None),
            DeliveryOutcome::Failed(413)
        );
        assert_eq!(urgency("default"), "normal");
    }
}
