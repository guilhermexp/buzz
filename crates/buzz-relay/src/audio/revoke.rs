//! Huddle access revocation when channel membership ends.
//!
//! Huddle access derives from channel membership: a member of a channel may
//! join its huddles (ephemeral channels linked to it by a creator-signed
//! `huddle_started` event, with auto-add), or audio in the channel itself.
//! When that membership ends (removal, self-leave, admin kick), this module
//! ends the derived access on this pod:
//!
//! 1. revokes the member's derived memberships in linked huddle channels (so
//!    neither an existing membership nor auto-add from the parent admits a
//!    rejoin), invalidating caches and live subscriptions for each;
//! 2. terminates every audio connection the member holds in the channel's
//!    own room and in linked huddle rooms. Each receives one
//!    [`MEMBERSHIP_REVOKED_FRAME`] before the WebSocket closes, then the normal
//!    leave teardown broadcasts `left` and emits the 48102 lifecycle event.
//!
//! Like subscription eviction, socket termination is pod-local; the durable
//! membership writes are what refuse the member on every pod.

use std::collections::BTreeSet;
use std::sync::Arc;

use buzz_core::tenant::TenantContext;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;

/// Final control frame sent to an audio connection whose access was revoked.
/// Clients treat `code: membership_revoked` as terminal (no reconnect).
pub const MEMBERSHIP_REVOKED_FRAME: &str =
    r#"{"type":"error","code":"membership_revoked","message":"error: membership revoked"}"#;

/// End `pubkey`'s huddle access derived from its (already removed)
/// membership in `channel_id`. Returns the huddle channels whose derived
/// membership was revoked, so the caller can evict their live subscriptions.
///
/// Live audio connections are terminated even when the durable revocation
/// fails; that error is then returned. A failed lookup of other live linked
/// rooms is logged: those rooms' admission still refuses a rejoin.
pub(crate) async fn revoke_huddle_access(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    channel_id: Uuid,
    pubkey: &[u8],
) -> anyhow::Result<Vec<Uuid>> {
    let community = tenant.community();
    let pubkey_hex = hex::encode(pubkey);
    let relay_pubkey = state.relay_keypair.public_key().to_bytes();

    let revoked = state
        .db
        .revoke_derived_huddle_memberships(community, channel_id, pubkey, &relay_pubkey)
        .await;
    if let Ok(revoked) = &revoked {
        for session in revoked {
            state.invalidate_membership(tenant, *session, pubkey);
        }
    }

    // Rooms to close: the channel's own room, every huddle whose derived
    // membership was just revoked, and any other live room of the member
    // linked to the channel (e.g. a huddle in an open session channel).
    let mut rooms: BTreeSet<Uuid> = BTreeSet::from([channel_id]);
    if let Ok(revoked) = &revoked {
        rooms.extend(revoked.iter().copied());
    }
    let live: Vec<Uuid> = state
        .audio_rooms
        .channels_with_pubkey(community, &pubkey_hex)
        .into_iter()
        .filter(|room| !rooms.contains(room))
        .collect();
    if !live.is_empty() {
        match state
            .db
            .huddle_started_links(community, &[channel_id], &live)
            .await
        {
            Ok(links) => rooms.extend(
                links
                    .into_iter()
                    .filter(|(_, parent, _)| *parent == channel_id)
                    .map(|(session, ..)| session),
            ),
            Err(e) => warn!(
                channel = %channel_id,
                error = %e,
                "huddle link lookup failed during audio revocation"
            ),
        }
    }

    let mut closed = 0;
    for room in &rooms {
        if let Some(room) = state.audio_rooms.get(community, *room) {
            closed += room.revoke_pubkey(&pubkey_hex, MEMBERSHIP_REVOKED_FRAME);
        }
    }
    if closed > 0 {
        info!(
            channel = %channel_id,
            target = %pubkey_hex,
            closed,
            "closed audio connections after channel membership ended"
        );
    }

    revoked.map_err(Into::into)
}
