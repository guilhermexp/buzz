//! E2E: WAV voice notes through Blossom `/upload` and message `imeta`.
//!
//! A canonical 16-bit PCM WAV (what Buzz recorders emit) uploads unchanged:
//! the descriptor's `sha256` is the client's hash, the blob is served as an
//! `audio/wav` attachment with `nosniff`, and a message whose `imeta` carries
//! the voice note's `duration` is accepted. Metadata chunks are refused, not
//! stripped, and every other audio container stays refused.
//!
//! ```text
//! RELAY_HTTP_URL=http://127.0.0.1:47300 \
//!   cargo test -p buzz-test-client --test e2e_media_voice_note -- --ignored
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use buzz_test_client::BuzzTestClient;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn relay_http_url() -> String {
    std::env::var("RELAY_HTTP_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn blossom_auth(keys: &Keys, verb: &str, sha256: &str) -> String {
    let server = relay_http_url()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();
    let expiration = (Timestamp::now().as_secs() + 55).to_string();
    let event = EventBuilder::new(Kind::from(24242), "voice note test")
        .tags([
            Tag::parse(["t", verb]).unwrap(),
            Tag::parse(["x", sha256]).unwrap(),
            Tag::parse(["expiration", &expiration]).unwrap(),
            Tag::parse(["server", &server]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap();
    format!("Nostr {}", URL_SAFE_NO_PAD.encode(event.as_json()))
}

async fn upload(keys: &Keys, body: &[u8]) -> reqwest::Response {
    let sha256 = hex::encode(Sha256::digest(body));
    reqwest::Client::new()
        .put(format!("{}/upload", relay_http_url()))
        .header("Authorization", blossom_auth(keys, "upload", &sha256))
        .header("X-SHA-256", &sha256)
        .timeout(Duration::from_secs(15))
        .body(body.to_vec())
        .send()
        .await
        .expect("upload request")
}

/// Mono 16-bit 24 kHz PCM WAV of `frames` samples, with optional extra chunk
/// inserted before `data`.
fn voice_note_wav(frames: u32, extra_chunk: Option<(&[u8; 4], &[u8])>) -> Vec<u8> {
    let mut chunks = b"fmt \x10\x00\x00\x00\x01\x00\x01\x00".to_vec();
    chunks.extend_from_slice(&24_000u32.to_le_bytes());
    chunks.extend_from_slice(&48_000u32.to_le_bytes());
    chunks.extend_from_slice(&[2, 0, 16, 0]);
    if let Some((id, body)) = extra_chunk {
        chunks.extend_from_slice(id);
        chunks.extend_from_slice(&(body.len() as u32).to_le_bytes());
        chunks.extend_from_slice(body);
    }
    chunks.extend_from_slice(b"data");
    chunks.extend_from_slice(&(frames * 2).to_le_bytes());
    for i in 0..frames {
        let sample = ((i as f32 * 0.05).sin() * 8_000.0) as i16;
        chunks.extend_from_slice(&sample.to_le_bytes());
    }
    let mut wav = b"RIFF".to_vec();
    wav.extend_from_slice(&(chunks.len() as u32 + 4).to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(&chunks);
    wav
}

#[tokio::test]
#[ignore]
async fn canonical_voice_note_uploads_unchanged_and_posts_with_duration() {
    let keys = Keys::generate();
    let wav = voice_note_wav(12_000, None); // 0.5 s
    let local_sha = hex::encode(Sha256::digest(&wav));

    let response = upload(&keys, &wav).await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let descriptor: serde_json::Value = response.json().await.unwrap();
    assert_eq!(descriptor["type"], "audio/wav", "{descriptor}");
    assert_eq!(
        descriptor["sha256"],
        local_sha.as_str(),
        "bytes stored unmodified"
    );
    assert_eq!(descriptor["size"], wav.len() as u64);
    assert!((descriptor["duration"].as_f64().unwrap() - 0.5).abs() < 1e-9);
    let url = descriptor["url"].as_str().unwrap().to_string();
    assert!(url.ends_with(&format!("{local_sha}.wav")), "{url}");

    let served = reqwest::Client::new()
        .get(&url)
        .header("Authorization", blossom_auth(&keys, "get", &local_sha))
        .send()
        .await
        .expect("GET voice note");
    assert_eq!(served.status(), 200);
    let header = |name: &str| {
        served
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(header("content-type"), "audio/wav");
    assert_eq!(header("content-disposition"), "attachment");
    assert_eq!(header("x-content-type-options"), "nosniff");
    assert_eq!(served.bytes().await.unwrap().as_ref(), wav.as_slice());

    // A channel message attaching the voice note with its duration is accepted.
    let ws_url = relay_http_url().replacen("http", "ws", 1);
    let mut client = BuzzTestClient::connect(&ws_url, &keys)
        .await
        .expect("connect");
    let channel = uuid::Uuid::new_v4().to_string();
    let create = EventBuilder::new(Kind::Custom(9007), "")
        .tags([
            Tag::parse(["h", &channel]).unwrap(),
            Tag::parse(["name", "voice-note-e2e"]).unwrap(),
            Tag::parse(["channel_type", "stream"]).unwrap(),
            Tag::parse(["visibility", "private"]).unwrap(),
        ])
        .sign_with_keys(&keys)
        .unwrap();
    let ok = client.send_event(create).await.expect("create channel");
    assert!(ok.accepted, "{}", ok.message);
    let imeta = [
        "imeta".to_string(),
        format!("url {url}"),
        "m audio/wav".to_string(),
        format!("x {local_sha}"),
        format!("size {}", wav.len()),
        "duration 0.5".to_string(),
        "filename voice-note-1760000000000.wav".to_string(),
    ];
    let message = EventBuilder::new(Kind::Custom(9), url.as_str())
        .tags([
            Tag::parse(["h", &channel]).unwrap(),
            Tag::parse(imeta).unwrap(),
        ])
        .sign_with_keys(&keys)
        .unwrap();
    let ok = client.send_event(message).await.expect("post voice note");
    assert!(ok.accepted, "voice note message rejected: {}", ok.message);
    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn wav_metadata_and_other_audio_are_refused() {
    let keys = Keys::generate();

    let tagged = voice_note_wav(2_400, Some((b"LIST", b"INFOINAM\x04\x00\x00\x00home")));
    let response = upload(&keys, &tagged).await;
    assert_eq!(response.status(), 422, "LIST/INFO metadata must be refused");

    let mut trailing = voice_note_wav(2_400, None);
    trailing.extend_from_slice(b"junk");
    let response = upload(&keys, &trailing).await;
    assert_eq!(response.status(), 422, "trailing bytes must be refused");

    let mp3 = b"ID3\x04\x00\x00\x00\x00\x00\x00";
    let response = upload(&keys, mp3).await;
    assert_eq!(response.status(), 415, "non-WAV audio stays refused");
}
