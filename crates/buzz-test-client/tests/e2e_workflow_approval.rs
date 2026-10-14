//! Relay-backed witness for durable workflow approval gates.
//!
//! These tests own the relay *process*: each one starts the real
//! `buzz-relay` binary, drives it through public Nostr/HTTP contracts, kills
//! it with SIGKILL and starts it again against the same isolated database.
//! A suspended run must survive that restart, accept only the designated
//! approver's decision, and continue (or stop) exactly once.
//!
//! # Running
//!
//! Provision an isolated, disposable Postgres/Redis/object store, seed the
//! relay's host community, then point the tests at a relay binary and an
//! environment file (KEY=VALUE lines, never printed):
//!
//! ```text
//! BUZZ_PARITY_RELAY_BIN=target/debug/buzz-relay \
//! BUZZ_PARITY_RELAY_ENV=/path/to/relay.env \
//! BUZZ_PARITY_RELAY_LOG=/path/to/relay.log \
//! cargo test -p buzz-test-client --test e2e_workflow_approval -- --ignored --test-threads=1
//! ```

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use base64::Engine as _;
use buzz_test_client::BuzzTestClient;
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{Alphabet, Event, EventBuilder, Filter, Keys, Kind, SingleLetterTag, Tag, Url};
use serde_json::Value;
use tokio::process::{Child, Command};
use uuid::Uuid;

const KIND_STREAM_MESSAGE: u16 = 9;
const KIND_WORKFLOW_DEFINITION: u16 = 30_620;
const KIND_WORKFLOW_TRIGGER: u16 = 46_020;
const KIND_APPROVAL_GRANT: u16 = 46_030;
const KIND_APPROVAL_DENY: u16 = 46_031;
const KIND_APPROVAL_REQUESTED: u16 = 46_010;

/// Each test restarts the shared relay port; serialize them even when the
/// harness is run without `--test-threads=1`.
static RELAY_PROCESS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ── Relay process ────────────────────────────────────────────────────────────

struct RelayProcess {
    bin: String,
    env: HashMap<String, String>,
    log_path: String,
    child: Option<Child>,
}

impl RelayProcess {
    fn from_environment() -> Self {
        let bin = std::env::var("BUZZ_PARITY_RELAY_BIN")
            .expect("BUZZ_PARITY_RELAY_BIN must name the relay binary under test");
        let env_path = std::env::var("BUZZ_PARITY_RELAY_ENV")
            .expect("BUZZ_PARITY_RELAY_ENV must name the isolated relay environment file");
        let log_path = std::env::var("BUZZ_PARITY_RELAY_LOG")
            .expect("BUZZ_PARITY_RELAY_LOG must name the relay log destination");
        let raw = std::fs::read_to_string(&env_path).expect("read relay environment file");
        let env = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
            .collect::<HashMap<_, _>>();
        for required in ["DATABASE_URL", "RELAY_URL", "BUZZ_BIND_ADDR"] {
            assert!(
                env.contains_key(required),
                "relay environment file is missing {required}"
            );
        }
        Self {
            bin,
            env,
            log_path,
            child: None,
        }
    }

    fn ws_url(&self) -> String {
        self.env["RELAY_URL"].clone()
    }

    fn http_base(&self) -> String {
        self.ws_url()
            .replace("wss://", "https://")
            .replace("ws://", "http://")
            .trim_end_matches('/')
            .to_string()
    }

    async fn port_is_open(&self) -> bool {
        tokio::net::TcpStream::connect(&self.env["BUZZ_BIND_ADDR"])
            .await
            .is_ok()
    }

    async fn start(&mut self) {
        assert!(self.child.is_none(), "relay already started by this test");
        // A previous test's relay is SIGKILLed when its handle drops (including
        // on panic); give the kernel a bounded window to release the port.
        let released = tokio::time::timeout(Duration::from_secs(15), async {
            while self.port_is_open().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            released.is_ok(),
            "relay port {} is already serving; refusing to test a process this witness does not own",
            self.env["BUZZ_BIND_ADDR"]
        );
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .expect("open relay log");
        let child = Command::new(&self.bin)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .envs(&self.env)
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("clone relay log handle"))
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .expect("spawn relay binary");
        self.child = Some(child);

        let health = format!("{}/health", self.http_base());
        let client = http_client();
        let ready = tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Some(child) = self.child.as_mut() {
                    if let Ok(Some(status)) = child.try_wait() {
                        panic!("relay exited during startup: {status}");
                    }
                }
                if let Ok(response) = client.get(&health).send().await {
                    if response.status().is_success() {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(ready.is_ok(), "relay did not become healthy within 90s");
    }

    /// Simulate a crash: SIGKILL, no graceful drain.
    async fn kill(&mut self) {
        let mut child = self.child.take().expect("relay is running");
        child.start_kill().expect("SIGKILL relay");
        child.wait().await.expect("reap relay");
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            while self.port_is_open().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(closed.is_ok(), "relay port stayed open after SIGKILL");
    }

    async fn restart(&mut self) {
        self.kill().await;
        self.start().await;
    }
}

// ── Protocol helpers ─────────────────────────────────────────────────────────

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build HTTP client")
}

fn sub_id(phase: &str) -> String {
    format!("e2e-workflow-approval-{phase}-{}", Uuid::new_v4())
}

fn nip98_header(keys: &Keys, url: &str) -> String {
    let data = HttpData::new(Url::parse(url).expect("NIP-98 URL"), HttpMethod::GET);
    // Polls can sign twice within one second; a nonce keeps each event id
    // unique so the relay's NIP-98 replay guard does not reject honest reads.
    let event = EventBuilder::http_auth(data)
        .tag(Tag::parse(["nonce", Uuid::new_v4().to_string().as_str()]).expect("nonce tag"))
        .sign_with_keys(keys)
        .expect("sign NIP-98 event");
    let json = serde_json::to_string(&event).expect("serialize NIP-98 event");
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(json)
    )
}

async fn signed_get(relay: &RelayProcess, keys: &Keys, path: &str) -> (u16, Value) {
    let url = format!("{}{path}", relay.http_base());
    let response = http_client()
        .get(&url)
        .header("Authorization", nip98_header(keys, &url))
        .send()
        .await
        .expect("signed GET");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

async fn connect(relay: &RelayProcess, keys: &Keys) -> BuzzTestClient {
    BuzzTestClient::connect(&relay.ws_url(), keys)
        .await
        .expect("connect authenticated client")
}

async fn accept(client: &mut BuzzTestClient, event: Event, what: &str) {
    let response = client.send_event(event).await.expect(what);
    assert!(response.accepted, "{what} rejected: {}", response.message);
}

/// Owner creates a private stream channel and adds the approver as a member.
async fn create_channel_with_member(
    client: &mut BuzzTestClient,
    owner: &Keys,
    member: &Keys,
) -> String {
    let channel_id = Uuid::new_v4().to_string();
    let create = EventBuilder::new(Kind::Custom(9007), "")
        .tags([
            Tag::parse(["h", channel_id.as_str()]).expect("h"),
            Tag::parse(["name", "workflow-approval-e2e"]).expect("name"),
            Tag::parse(["channel_type", "stream"]).expect("type"),
            Tag::parse(["visibility", "private"]).expect("visibility"),
        ])
        .sign_with_keys(owner)
        .expect("sign channel creation");
    accept(client, create, "channel creation").await;
    let add = EventBuilder::new(Kind::Custom(9000), "")
        .tags([
            Tag::parse(["h", channel_id.as_str()]).expect("h"),
            Tag::parse(["p", member.public_key().to_hex().as_str()]).expect("p"),
        ])
        .sign_with_keys(owner)
        .expect("sign member addition");
    accept(client, add, "approver membership").await;
    channel_id
}

fn approval_workflow_yaml(nonce: &str, approver_hex: &str, timeout: &str) -> String {
    format!(
        "name: approval-witness-{nonce}\n\
         trigger:\n  on: webhook\n\
         steps:\n\
         \x20 - id: before\n    action: send_message\n    text: 'wf-{nonce} before approval'\n\
         \x20 - id: gate\n    action: request_approval\n    from: '{approver_hex}'\n    message: 'Release wf-{nonce}?'\n    timeout: {timeout}\n\
         \x20 - id: after\n    action: send_message\n    text: 'wf-{nonce} after approval'\n"
    )
}

async fn create_and_trigger(
    client: &mut BuzzTestClient,
    owner: &Keys,
    channel_id: &str,
    yaml: &str,
) -> String {
    let workflow_id = Uuid::new_v4().to_string();
    let definition = EventBuilder::new(Kind::Custom(KIND_WORKFLOW_DEFINITION), yaml)
        .tags([
            Tag::parse(["d", workflow_id.as_str()]).expect("d"),
            Tag::parse(["h", channel_id]).expect("h"),
        ])
        .sign_with_keys(owner)
        .expect("sign workflow definition");
    accept(client, definition, "workflow definition").await;
    let trigger = EventBuilder::new(Kind::Custom(KIND_WORKFLOW_TRIGGER), "{}")
        .tags([Tag::parse(["d", workflow_id.as_str()]).expect("d")])
        .sign_with_keys(owner)
        .expect("sign workflow trigger");
    accept(client, trigger, "manual workflow trigger").await;
    workflow_id
}

/// Poll the authorized run read model until the single run leaves the
/// transient states (`pending`/`running`).
async fn settled_run(relay: &RelayProcess, reader: &Keys, workflow_id: &str) -> Value {
    let path = format!("/workflows/{workflow_id}/runs");
    let mut last = Value::Null;
    for _ in 0..150 {
        let (status, body) = signed_get(relay, reader, &path).await;
        assert_eq!(status, 200, "run read rejected: {body}");
        if let Some(run) = body["runs"].as_array().and_then(|runs| runs.first()) {
            last = run.clone();
            let state = run["status"].as_str().unwrap_or_default();
            if state != "pending" && state != "running" {
                return run.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("workflow run did not settle within 30s; last observed: {last}");
}

async fn run_approvals(
    relay: &RelayProcess,
    reader: &Keys,
    workflow_id: &str,
    run_id: &str,
) -> Vec<Value> {
    let (status, body) = signed_get(
        relay,
        reader,
        &format!("/workflows/{workflow_id}/runs/{run_id}/approvals"),
    )
    .await;
    assert_eq!(status, 200, "approval read rejected: {body}");
    body["approvals"].as_array().cloned().unwrap_or_default()
}

async fn channel_events(client: &mut BuzzTestClient, channel_id: &str, kind: u16) -> Vec<Event> {
    let subscription = sub_id("channel-query");
    client
        .subscribe(
            &subscription,
            vec![Filter::new()
                .kind(Kind::Custom(kind))
                .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel_id])],
        )
        .await
        .expect("subscribe channel query");
    let events = client
        .collect_until_eose(&subscription, Duration::from_secs(5))
        .await
        .expect("collect channel events");
    client
        .close_subscription(&subscription)
        .await
        .expect("close channel query");
    events
}

async fn message_count(client: &mut BuzzTestClient, channel_id: &str, text: &str) -> usize {
    channel_events(client, channel_id, KIND_STREAM_MESSAGE)
        .await
        .iter()
        .filter(|event| event.content == text)
        .count()
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some(name))
            .then(|| parts.get(1).map(String::as_str))
            .flatten()
    })
}

fn decision(keys: &Keys, kind: u16, approval_ref: &str) -> Event {
    EventBuilder::new(Kind::Custom(kind), "")
        .tags([Tag::parse(["d", approval_ref]).expect("d")])
        .sign_with_keys(keys)
        .expect("sign approval decision")
}

/// Shared prefix: a run suspended at its approval gate, observed through the
/// read model and the approver's channel request event.
struct SuspendedRun {
    nonce: String,
    channel_id: String,
    workflow_id: String,
    run_id: String,
    approval_ref: String,
}

async fn suspend_run(
    relay: &RelayProcess,
    owner: &Keys,
    approver: &Keys,
    timeout: &str,
) -> SuspendedRun {
    let nonce = Uuid::new_v4().simple().to_string();
    let mut owner_client = connect(relay, owner).await;
    let channel_id = create_channel_with_member(&mut owner_client, owner, approver).await;
    let yaml = approval_workflow_yaml(&nonce, &approver.public_key().to_hex(), timeout);
    let workflow_id = create_and_trigger(&mut owner_client, owner, &channel_id, &yaml).await;
    owner_client.disconnect().await.expect("disconnect owner");

    // witness: suspended_run_is_waiting_approval
    let run = settled_run(relay, approver, &workflow_id).await;
    assert_eq!(
        run["status"], "waiting_approval",
        "approval gate must suspend the run, not end it: {run}"
    );
    assert_eq!(
        run["error_code"],
        Value::Null,
        "suspended run carries no error: {run}"
    );
    let run_id = run["id"].as_str().expect("run id").to_string();

    // witness: pending_approval_is_persisted
    let approvals = run_approvals(relay, approver, &workflow_id, &run_id).await;
    assert_eq!(
        approvals.len(),
        1,
        "exactly one approval record: {approvals:?}"
    );
    assert_eq!(approvals[0]["status"], "pending");
    assert_eq!(approvals[0]["step_id"], "gate");
    let approval_ref = approvals[0]["approval_ref"]
        .as_str()
        .expect("approval ref")
        .to_string();

    // witness: approver_receives_request_event
    let mut approver_client = connect(relay, approver).await;
    let requests = channel_events(&mut approver_client, &channel_id, KIND_APPROVAL_REQUESTED).await;
    assert_eq!(
        requests.len(),
        1,
        "one approval request event: {requests:?}"
    );
    assert_eq!(tag_value(&requests[0], "d"), Some(approval_ref.as_str()));
    assert!(
        requests[0].tags.iter().any(|tag| {
            let parts = tag.as_slice();
            parts.first().map(String::as_str) == Some("p")
                && parts.get(1) == Some(&approver.public_key().to_hex())
        }),
        "approval request must address the designated approver"
    );
    assert_eq!(
        message_count(
            &mut approver_client,
            &channel_id,
            &format!("wf-{nonce} before approval")
        )
        .await,
        1
    );
    approver_client
        .disconnect()
        .await
        .expect("disconnect approver");

    SuspendedRun {
        nonce,
        channel_id,
        workflow_id,
        run_id,
        approval_ref,
    }
}

// ── Witnesses ────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn approval_gate_survives_restart_and_resumes_exactly_once() {
    let _serial = RELAY_PROCESS_LOCK.lock().await;
    let mut relay = RelayProcess::from_environment();
    relay.start().await;
    let owner = Keys::generate();
    let approver = Keys::generate();
    let suspended = suspend_run(&relay, &owner, &approver, "1h").await;

    // witness: suspension_survives_relay_crash
    relay.restart().await;
    let run = settled_run(&relay, &approver, &suspended.workflow_id).await;
    assert_eq!(run["status"], "waiting_approval", "after restart: {run}");

    // witness: non_designated_decision_is_rejected
    let mut owner_client = connect(&relay, &owner).await;
    let forged = owner_client
        .send_event(decision(
            &owner,
            KIND_APPROVAL_GRANT,
            &suspended.approval_ref,
        ))
        .await
        .expect("submit non-approver grant");
    assert!(
        !forged.accepted,
        "workflow owner is not the designated approver"
    );
    owner_client.disconnect().await.expect("disconnect owner");
    let run = settled_run(&relay, &approver, &suspended.workflow_id).await;
    assert_eq!(
        run["status"], "waiting_approval",
        "rejected decision must not advance: {run}"
    );

    // witness: granted_run_completes_once
    let mut approver_client = connect(&relay, &approver).await;
    let grant = decision(&approver, KIND_APPROVAL_GRANT, &suspended.approval_ref);
    accept(
        &mut approver_client,
        grant.clone(),
        "designated approver grant",
    )
    .await;
    let run = settled_run(&relay, &approver, &suspended.workflow_id).await;
    assert_eq!(run["status"], "completed", "granted run must finish: {run}");
    let after = format!("wf-{} after approval", suspended.nonce);
    let before = format!("wf-{} before approval", suspended.nonce);
    assert_eq!(
        message_count(&mut approver_client, &suspended.channel_id, &after).await,
        1
    );
    assert_eq!(
        message_count(&mut approver_client, &suspended.channel_id, &before).await,
        1
    );
    let approvals =
        run_approvals(&relay, &approver, &suspended.workflow_id, &suspended.run_id).await;
    assert_eq!(approvals[0]["status"], "granted");
    assert_eq!(
        approvals[0]["approver_pubkey"],
        Value::String(approver.public_key().to_hex())
    );

    // witness: replayed_decision_does_not_duplicate
    let replay = approver_client
        .send_event(decision(
            &approver,
            KIND_APPROVAL_GRANT,
            &suspended.approval_ref,
        ))
        .await
        .expect("submit replayed grant");
    assert!(
        !replay.accepted,
        "a decided approval cannot be granted again"
    );
    let duplicate = approver_client
        .send_event(grant)
        .await
        .expect("resubmit identical grant");
    assert!(
        !duplicate.accepted || duplicate.message.starts_with("duplicate"),
        "identical grant must be rejected or acknowledged as a duplicate: {}",
        duplicate.message
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        message_count(&mut approver_client, &suspended.channel_id, &after).await,
        1
    );
    approver_client
        .disconnect()
        .await
        .expect("disconnect approver");
}

#[tokio::test]
#[ignore]
async fn granted_decision_survives_crash_before_resume() {
    let _serial = RELAY_PROCESS_LOCK.lock().await;
    let mut relay = RelayProcess::from_environment();
    relay.start().await;
    let owner = Keys::generate();
    let approver = Keys::generate();
    let suspended = suspend_run(&relay, &owner, &approver, "1h").await;

    // Crash immediately after the grant is acknowledged; recovery must finish
    // the run without losing or repeating the post-approval step.
    let mut approver_client = connect(&relay, &approver).await;
    accept(
        &mut approver_client,
        decision(&approver, KIND_APPROVAL_GRANT, &suspended.approval_ref),
        "designated approver grant",
    )
    .await;
    relay.restart().await;

    // witness: granted_decision_recovers_after_crash
    let run = settled_run(&relay, &approver, &suspended.workflow_id).await;
    assert_eq!(
        run["status"], "completed",
        "granted run must recover: {run}"
    );
    let mut approver_client = connect(&relay, &approver).await;
    let after = format!("wf-{} after approval", suspended.nonce);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        message_count(&mut approver_client, &suspended.channel_id, &after).await,
        1
    );
    approver_client
        .disconnect()
        .await
        .expect("disconnect approver");
}

#[tokio::test]
#[ignore]
async fn denied_approval_cancels_without_continuation() {
    let _serial = RELAY_PROCESS_LOCK.lock().await;
    let mut relay = RelayProcess::from_environment();
    relay.start().await;
    let owner = Keys::generate();
    let approver = Keys::generate();
    let suspended = suspend_run(&relay, &owner, &approver, "1h").await;
    relay.restart().await;

    // witness: denied_run_is_cancelled
    let mut approver_client = connect(&relay, &approver).await;
    accept(
        &mut approver_client,
        decision(&approver, KIND_APPROVAL_DENY, &suspended.approval_ref),
        "designated approver denial",
    )
    .await;
    let run = settled_run(&relay, &approver, &suspended.workflow_id).await;
    assert_eq!(run["status"], "cancelled", "denied run must stop: {run}");
    assert_eq!(run["error_code"], "approval_denied");
    let late_grant = approver_client
        .send_event(decision(
            &approver,
            KIND_APPROVAL_GRANT,
            &suspended.approval_ref,
        ))
        .await
        .expect("submit grant after denial");
    assert!(
        !late_grant.accepted,
        "a denied approval cannot later be granted"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = format!("wf-{} after approval", suspended.nonce);
    assert_eq!(
        message_count(&mut approver_client, &suspended.channel_id, &after).await,
        0
    );
    approver_client
        .disconnect()
        .await
        .expect("disconnect approver");
}

#[tokio::test]
#[ignore]
async fn expired_approval_fails_run_even_across_restart() {
    let _serial = RELAY_PROCESS_LOCK.lock().await;
    let mut relay = RelayProcess::from_environment();
    relay.start().await;
    let owner = Keys::generate();
    let approver = Keys::generate();
    let suspended = suspend_run(&relay, &owner, &approver, "8s").await;

    // Let the deadline pass while the relay is down.
    relay.kill().await;
    tokio::time::sleep(Duration::from_secs(9)).await;
    relay.start().await;

    // witness: expired_approval_terminates_run
    let mut expired = Value::Null;
    for _ in 0..100 {
        let run = settled_run(&relay, &approver, &suspended.workflow_id).await;
        if run["status"] != "waiting_approval" {
            expired = run;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        expired["status"], "failed",
        "expired approval must end the run: {expired}"
    );
    assert_eq!(expired["error_code"], "approval_expired");
    let approvals =
        run_approvals(&relay, &approver, &suspended.workflow_id, &suspended.run_id).await;
    assert_eq!(approvals[0]["status"], "expired");

    let mut approver_client = connect(&relay, &approver).await;
    let late = approver_client
        .send_event(decision(
            &approver,
            KIND_APPROVAL_GRANT,
            &suspended.approval_ref,
        ))
        .await
        .expect("submit grant after expiry");
    assert!(!late.accepted, "an expired approval cannot be granted");
    let after = format!("wf-{} after approval", suspended.nonce);
    assert_eq!(
        message_count(&mut approver_client, &suspended.channel_id, &after).await,
        0
    );
    approver_client
        .disconnect()
        .await
        .expect("disconnect approver");
}
