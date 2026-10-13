//! E2E: removing a member from a channel revokes their live huddle audio.
//!
//! Two real audio WebSocket peers join a private channel's huddle through the
//! relay and exchange frames. When the channel owner removes one of them
//! (kind 9001), the relay must close the removed peer's audio socket — after a
//! terminal `membership_revoked` frame and with no audio after it — announce
//! the departure to the remaining peer, record the leave (kind 48102), and
//! refuse the removed member's rejoin. The remaining peer keeps its session.
//!
//! Requires a running relay; ignored by default:
//!
//! ```text
//! RELAY_URL=ws://127.0.0.1:47300 \
//!   cargo test -p buzz-test-client --test e2e_huddle_revocation -- --ignored
//! ```

use std::time::Duration;

use buzz_test_client::BuzzTestClient;
use futures_util::{SinkExt, StreamExt};
use nostr::{Alphabet, EventBuilder, Filter, JsonUtil, Keys, Kind, SingleLetterTag, Tag};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

type AudioSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const KIND_HUDDLE_STARTED: u16 = 48100;
const KIND_HUDDLE_PARTICIPANT_LEFT: u16 = 48102;
const STEP: Duration = Duration::from_secs(10);

fn relay_url() -> String {
    std::env::var("RELAY_URL")
        .unwrap_or_else(|_| "ws://localhost:3000".to_string())
        .trim_end_matches('/')
        .to_string()
}

async fn submit(
    client: &mut BuzzTestClient,
    keys: &Keys,
    kind: u16,
    content: &str,
    tags: &[&[&str]],
) {
    let tags: Vec<Tag> = tags
        .iter()
        .map(|t| Tag::parse(t.iter().copied()).expect("tag"))
        .collect();
    let event = EventBuilder::new(Kind::Custom(kind), content)
        .tags(tags)
        .sign_with_keys(keys)
        .expect("sign event");
    let ok = client.send_event(event).await.expect("send event");
    assert!(ok.accepted, "kind {kind} rejected: {}", ok.message);
}

/// Owner creates private parent `P` with both members, then starts a huddle
/// the way Buzz clients do: an ephemeral private channel `H` (ttl) linked to
/// `P` by a creator-signed kind 48100.
async fn start_huddle(owner: &Keys, members: [&Keys; 2]) -> (BuzzTestClient, String, String) {
    let mut client = BuzzTestClient::connect(&relay_url(), owner)
        .await
        .expect("owner connects");
    let parent = Uuid::new_v4().to_string();
    submit(
        &mut client,
        owner,
        9007,
        "",
        &[
            &["h", &parent],
            &["name", "huddle-revocation-e2e"],
            &["channel_type", "stream"],
            &["visibility", "private"],
        ],
    )
    .await;
    for member in members {
        let pubkey = member.public_key().to_hex();
        submit(
            &mut client,
            owner,
            9000,
            "",
            &[&["h", &parent], &["p", &pubkey]],
        )
        .await;
    }
    let huddle = Uuid::new_v4().to_string();
    submit(
        &mut client,
        owner,
        9007,
        "",
        &[
            &["h", &huddle],
            &["name", &format!("huddle-{}", &huddle[..8])],
            &["channel_type", "stream"],
            &["visibility", "private"],
            &["ttl", "3600"],
        ],
    )
    .await;
    let started = serde_json::json!({ "ephemeral_channel_id": huddle }).to_string();
    submit(
        &mut client,
        owner,
        KIND_HUDDLE_STARTED,
        &started,
        &[&["h", &parent]],
    )
    .await;
    (client, parent, huddle)
}

/// Open `/huddle/{huddle}/audio`, answer the NIP-42 challenge and return the
/// socket with the relay's first text reply (`joined` or an error).
async fn open_audio(keys: &Keys, huddle: &str, parent: &str) -> (AudioSocket, serde_json::Value) {
    let base = relay_url();
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{base}/huddle/{huddle}/audio"))
        .await
        .expect("audio websocket connects");
    let challenge = next_text(&mut ws).await.expect("challenge frame");
    assert_eq!(challenge["type"], "challenge", "{challenge}");
    let auth = EventBuilder::new(Kind::Authentication, "")
        .tags([
            Tag::parse(["relay", base.as_str()]).expect("relay tag"),
            Tag::parse([
                "challenge",
                challenge["challenge"].as_str().expect("challenge"),
            ])
            .expect("challenge tag"),
        ])
        .sign_with_keys(keys)
        .expect("sign audio auth");
    let auth_msg = serde_json::json!({
        "type": "auth",
        "event": serde_json::from_str::<serde_json::Value>(&auth.as_json()).expect("auth json"),
        "parent_channel_id": parent,
        "protocol_version": 1,
    });
    ws.send(Message::Text(auth_msg.to_string().into()))
        .await
        .expect("send audio auth");
    let reply = next_text(&mut ws).await.expect("reply to audio auth");
    (ws, reply)
}

/// Next text frame as JSON, skipping pings; `None` once the socket closes.
async fn next_text(ws: &mut AudioSocket) -> Option<serde_json::Value> {
    loop {
        match tokio::time::timeout(STEP, ws.next())
            .await
            .expect("audio frame in time")
        {
            Some(Ok(Message::Text(text))) => {
                return Some(serde_json::from_str(&text).expect("text frame is JSON"))
            }
            Some(Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
            Some(Ok(_)) => continue,
        }
    }
}

/// Next binary audio frame, skipping control text; panics if the socket closes.
async fn next_audio(ws: &mut AudioSocket) -> Vec<u8> {
    loop {
        match tokio::time::timeout(STEP, ws.next())
            .await
            .expect("audio frame in time")
        {
            Some(Ok(Message::Binary(data))) => return data.to_vec(),
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => panic!("socket closed"),
            Some(Ok(_)) => continue,
        }
    }
}

async fn send_audio(ws: &mut AudioSocket, payload: &[u8]) {
    ws.send(Message::Binary(payload.to_vec().into()))
        .await
        .expect("send audio frame");
}

async fn left_events(client: &mut BuzzTestClient, parent: &str, pubkey: &str) -> usize {
    let sub = format!("huddle-left-{}", Uuid::new_v4());
    client
        .subscribe(
            &sub,
            vec![Filter::new()
                .kind(Kind::Custom(KIND_HUDDLE_PARTICIPANT_LEFT))
                .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [parent])],
        )
        .await
        .expect("subscribe 48102");
    let events = client
        .collect_until_eose(&sub, Duration::from_secs(5))
        .await
        .expect("collect 48102");
    client.close_subscription(&sub).await.expect("close sub");
    events
        .iter()
        .filter(|event| {
            event.tags.iter().any(|tag| {
                let parts = tag.as_slice();
                parts.first().map(String::as_str) == Some("p")
                    && parts.get(1).map(String::as_str) == Some(pubkey)
            })
        })
        .count()
}

#[tokio::test]
#[ignore]
async fn removed_member_loses_live_huddle_audio_and_cannot_rejoin() {
    let owner = Keys::generate();
    let removed = Keys::generate();
    let remaining = Keys::generate();
    let removed_hex = removed.public_key().to_hex();
    let (mut owner_client, parent, huddle) = start_huddle(&owner, [&removed, &remaining]).await;

    // Both members join through parent-derived auto-add.
    let (mut removed_ws, joined) = open_audio(&removed, &huddle, &parent).await;
    assert_eq!(joined["type"], "joined", "removed member joins: {joined}");
    let (mut remaining_ws, joined) = open_audio(&remaining, &huddle, &parent).await;
    assert_eq!(joined["type"], "joined", "remaining member joins: {joined}");
    let announced = next_text(&mut removed_ws).await.expect("join announcement");
    assert_eq!(announced["type"], "joined", "{announced}");

    // Audio flows both ways before removal (v1: one-byte peer prefix).
    send_audio(&mut removed_ws, b"before-removal-a").await;
    assert_eq!(
        &next_audio(&mut remaining_ws).await[1..],
        b"before-removal-a"
    );
    send_audio(&mut remaining_ws, b"before-removal-b").await;
    assert_eq!(&next_audio(&mut removed_ws).await[1..], b"before-removal-b");

    // Owner removes the member from the parent channel.
    submit(
        &mut owner_client,
        &owner,
        9001,
        "",
        &[&["h", &parent], &["p", &removed_hex]],
    )
    .await;

    // The removed socket gets the terminal frame, then closes with no audio.
    let mut terminal = None;
    loop {
        match tokio::time::timeout(STEP, removed_ws.next())
            .await
            .expect("removed socket must close promptly")
        {
            Some(Ok(Message::Text(text))) => {
                let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
                if value["type"] == "error" {
                    terminal = Some(value);
                }
            }
            Some(Ok(Message::Binary(_))) if terminal.is_some() => {
                panic!("audio delivered after membership revocation")
            }
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            Some(Ok(_)) => continue,
        }
    }
    let terminal = terminal.expect("membership_revoked frame before close");
    assert_eq!(terminal["code"], "membership_revoked", "{terminal}");

    // The remaining peer sees the departure and keeps its session.
    loop {
        let control = next_text(&mut remaining_ws)
            .await
            .expect("remaining socket stays open");
        if control["type"] == "left" {
            assert_eq!(control["pubkey"], removed_hex, "{control}");
            break;
        }
    }
    send_audio(&mut remaining_ws, b"after-removal").await;
    remaining_ws
        .send(Message::Ping(Vec::new().into()))
        .await
        .expect("remaining socket still writable");

    // The departure is recorded as a normal leave in the parent channel.
    let mut recorded = 0;
    for _ in 0..20 {
        recorded = left_events(&mut owner_client, &parent, &removed_hex).await;
        if recorded > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(recorded, 1, "exactly one 48102 for the removed member");

    // Rejoin is refused: no derived membership and no parent auto-add.
    let (mut rejoin_ws, refusal) = open_audio(&removed, &huddle, &parent).await;
    assert_eq!(
        refusal["type"], "error",
        "rejoin must be refused: {refusal}"
    );
    assert!(
        refusal["message"]
            .as_str()
            .is_some_and(|message| message.contains("not a member")),
        "{refusal}"
    );
    assert!(
        next_text(&mut rejoin_ws).await.is_none(),
        "refused socket closes"
    );

    let _ = remaining_ws.send(Message::Close(None)).await;
    owner_client.disconnect().await.expect("disconnect owner");
}
