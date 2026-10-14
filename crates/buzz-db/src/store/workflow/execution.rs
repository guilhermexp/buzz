//! Durable execution state for workflow runs.
//!
//! A run in `running` is owned by exactly one engine instance through a
//! renewable lease (`lease_owner`, `lease_expires_at`). Every state transition
//! that hands a run to or from an executor is a single compare-and-set on the
//! run row, so a stale executor (whose lease expired and was re-claimed) can
//! never overwrite the newer owner's progress, and a decided approval can be
//! resumed by at most one executor.
//!
//! Approval suspension and approval decisions are one atomic persist each:
//! the run transition, the approval row and the relay-signed notification
//! event commit together, so a crash can never leave a suspended run without
//! its pending approval or a granted approval without its resumable run.

use chrono::{DateTime, Utc};
use nostr::Event;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use buzz_core::{CommunityId, StoredEvent};

use super::{
    hash_approval_token, row_to_run_record, ApprovalStatus, RunStatus, WorkflowRunFailure,
    WorkflowRunRecord,
};
use crate::error::{DbError, Result};
use crate::{AdmittedTx, Db};

/// Identity and lifetime of an executor's claim on a running workflow run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLease {
    /// The claiming engine instance.
    pub owner: Uuid,
    /// Lease lifetime from the moment of each claim or renewal, in seconds.
    pub ttl_secs: i64,
}

/// Transition a freshly created `pending` run to `running` under `lease`.
///
/// Returns `false` when the run is no longer pending (already claimed or
/// cancelled), in which case the caller must not execute it.
pub async fn claim_pending_workflow_run(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    lease: RunLease,
) -> Result<bool> {
    let affected = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET status = 'running',
            lease_owner = $3,
            lease_expires_at = NOW() + make_interval(secs => $4),
            started_at = COALESCE(started_at, NOW())
        WHERE community_id = $1 AND id = $2 AND status = 'pending'
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(lease.owner)
    .bind(lease.ttl_secs as f64)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Extend the lease of a run this owner still holds. `false` means ownership
/// was lost (the run settled or another executor reclaimed it).
pub async fn renew_workflow_run_lease(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    lease: RunLease,
) -> Result<bool> {
    let affected = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET lease_expires_at = NOW() + make_interval(secs => $4)
        WHERE community_id = $1 AND id = $2 AND status = 'running' AND lease_owner = $3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(lease.owner)
    .bind(lease.ttl_secs as f64)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Persist step progress for a run this owner holds.
pub async fn checkpoint_workflow_run(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    owner: Uuid,
    current_step: i32,
    trace: &Value,
) -> Result<bool> {
    let affected = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET current_step = $4, execution_trace = $5
        WHERE community_id = $1 AND id = $2 AND status = 'running' AND lease_owner = $3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(owner)
    .bind(current_step)
    .bind(trace)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Move a run this owner holds to a terminal status and release the lease.
#[allow(clippy::too_many_arguments)]
pub async fn settle_workflow_run(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    owner: Uuid,
    status: RunStatus,
    current_step: i32,
    trace: &Value,
    failure: Option<WorkflowRunFailure<'_>>,
) -> Result<bool> {
    if !matches!(
        status,
        RunStatus::Completed | RunStatus::Failed | RunStatus::Cancelled
    ) {
        return Err(DbError::InvalidData(format!(
            "settle_workflow_run requires a terminal status, got {status}"
        )));
    }
    let (code, message) = failure
        .map(|failure| (Some(failure.code), Some(failure.message)))
        .unwrap_or((None, None));
    let affected = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET status = $4::run_status,
            current_step = $5,
            execution_trace = $6,
            error_code = $7,
            error_message = $8,
            completed_at = NOW(),
            lease_owner = NULL,
            lease_expires_at = NULL
        WHERE community_id = $1 AND id = $2 AND status = 'running' AND lease_owner = $3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(owner)
    .bind(status.to_string())
    .bind(current_step)
    .bind(trace)
    .bind(code)
    .bind(message)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Everything persisted atomically when a run reaches an approval gate.
pub struct ApprovalSuspension<'a> {
    /// Owning community.
    pub community_id: CommunityId,
    /// The suspended run, currently held by `owner`.
    pub run_id: Uuid,
    /// Executor that holds the run's lease.
    pub owner: Uuid,
    /// The run's workflow.
    pub workflow_id: Uuid,
    /// The workflow's channel, where the request event is stored.
    pub channel_id: Uuid,
    /// Raw approval token (stored hashed).
    pub token: &'a str,
    /// Gate step id.
    pub step_id: &'a str,
    /// Gate step index; also the run's `current_step` while suspended.
    pub step_index: i32,
    /// Normalized approver spec (hex pubkey or `any`).
    pub approver_spec: &'a str,
    /// Decision deadline.
    pub expires_at: DateTime<Utc>,
    /// Full trace including the gate's `waiting_approval` entry.
    pub trace: &'a Value,
    /// Relay-signed kind:46010 request event.
    pub request_event: &'a Event,
}

/// Suspend a held run at its approval gate.
///
/// Returns `None` (and changes nothing) when `owner` no longer holds the run.
pub async fn suspend_workflow_run_for_approval(
    db: &Db,
    suspension: ApprovalSuspension<'_>,
) -> Result<Option<StoredEvent>> {
    let mut tx = db
        .begin_event_write_transaction(suspension.community_id)
        .await?;
    let affected = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET status = 'waiting_approval',
            current_step = $4,
            execution_trace = $5,
            lease_owner = NULL,
            lease_expires_at = NULL
        WHERE community_id = $1 AND id = $2 AND status = 'running' AND lease_owner = $3
        "#,
    )
    .bind(suspension.community_id.as_uuid())
    .bind(suspension.run_id)
    .bind(suspension.owner)
    .bind(suspension.step_index)
    .bind(suspension.trace)
    .execute(tx.conn())
    .await?
    .rows_affected();
    if affected != 1 {
        tx.rollback().await?;
        return Ok(None);
    }
    sqlx::query(
        r#"
        INSERT INTO workflow_approvals
            (community_id, token, workflow_id, run_id, step_id, step_index, approver_spec,
             status, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)
        "#,
    )
    .bind(suspension.community_id.as_uuid())
    .bind(hash_approval_token(suspension.token))
    .bind(suspension.workflow_id)
    .bind(suspension.run_id)
    .bind(suspension.step_id)
    .bind(suspension.step_index)
    .bind(suspension.approver_spec)
    .bind(suspension.expires_at)
    .execute(tx.conn())
    .await?;
    let (stored, _) = crate::event::insert_event_in_transaction(
        &mut tx,
        suspension.request_event,
        Some(suspension.channel_id),
    )
    .await?;
    tx.commit().await?;
    Ok(Some(stored))
}

/// A designated approver's decision on a pending gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Continue the run after the gate.
    Grant,
    /// Cancel the run.
    Deny,
}

/// Parameters for [`decide_workflow_approval_in_transaction`].
pub struct DecideApproval<'a> {
    /// SHA-256 of the raw token, as referenced by the request event's `d` tag.
    pub token_hash: &'a [u8],
    /// The decision.
    pub decision: ApprovalDecision,
    /// Deciding identity (already authorized by the caller).
    pub approver_pubkey: &'a [u8],
    /// Optional note from the approver.
    pub note: Option<&'a str>,
    /// Lease taken on the run when granting, so exactly one executor resumes it.
    pub resume_lease: RunLease,
    /// Relay-signed kind:46011/46012 decision event.
    pub decision_event: &'a Event,
}

/// Result of a decision attempt.
#[derive(Debug)]
pub enum ApprovalDecisionOutcome {
    /// The decision was recorded; the run was resumed (grant) or cancelled.
    Applied {
        /// The decided run.
        run_id: Uuid,
        /// Its workflow.
        workflow_id: Uuid,
        /// The persisted decision event, for post-commit fan-out.
        decision_event: Box<StoredEvent>,
    },
    /// No approval exists for this reference in the transaction's community.
    NotFound,
    /// The approval was already decided or expired.
    NotPending(ApprovalStatus),
    /// The decision deadline has passed.
    Expired,
    /// The run is no longer waiting for this gate.
    RunNotWaiting(RunStatus),
}

/// Replace the gate's `waiting_approval` trace entry with its resolution.
pub fn resolve_gate_trace(trace: &Value, step_id: &str, resolution: Value) -> Value {
    let mut entries = trace.as_array().cloned().unwrap_or_default();
    let position = entries.iter().rposition(|entry| {
        entry.get("step_id").and_then(Value::as_str) == Some(step_id)
            && entry.get("status").and_then(Value::as_str) == Some("waiting_approval")
    });
    match position {
        Some(index) => entries[index] = resolution,
        None => entries.push(resolution),
    }
    Value::Array(entries)
}

/// Record a decision inside the caller's admitted transaction (which also
/// holds the client's command event), transitioning the run atomically.
pub async fn decide_workflow_approval_in_transaction(
    tx: &mut AdmittedTx,
    params: DecideApproval<'_>,
) -> Result<ApprovalDecisionOutcome> {
    let community = tx.community();
    let approval = sqlx::query(
        r#"
        SELECT run_id, workflow_id, step_id, step_index, status::text AS status,
               expires_at <= NOW() AS expired
        FROM workflow_approvals
        WHERE community_id = $1 AND token = $2
        FOR UPDATE
        "#,
    )
    .bind(community.as_uuid())
    .bind(params.token_hash)
    .fetch_optional(tx.conn())
    .await?;
    let Some(approval) = approval else {
        return Ok(ApprovalDecisionOutcome::NotFound);
    };
    let status: ApprovalStatus = approval.try_get::<String, _>("status")?.parse()?;
    if status != ApprovalStatus::Pending {
        return Ok(ApprovalDecisionOutcome::NotPending(status));
    }
    if approval.try_get::<bool, _>("expired")? {
        return Ok(ApprovalDecisionOutcome::Expired);
    }
    let run_id: Uuid = approval.try_get("run_id")?;
    let workflow_id: Uuid = approval.try_get("workflow_id")?;
    let step_id: String = approval.try_get("step_id")?;
    let step_index: i32 = approval.try_get("step_index")?;

    let run = sqlx::query(
        r#"
        SELECT community_id, id, workflow_id, status::text AS status, trigger_event_id,
               current_step, execution_trace, trigger_context, started_at, completed_at,
               error_message, error_code, created_at
        FROM workflow_runs WHERE community_id = $1 AND id = $2 FOR UPDATE
        "#,
    )
    .bind(community.as_uuid())
    .bind(run_id)
    .fetch_one(tx.conn())
    .await?;
    let run = row_to_run_record(run)?;
    if run.status != RunStatus::WaitingApproval {
        return Ok(ApprovalDecisionOutcome::RunNotWaiting(run.status));
    }

    let granted = params.decision == ApprovalDecision::Grant;
    let new_status = if granted {
        ApprovalStatus::Granted
    } else {
        ApprovalStatus::Denied
    };
    sqlx::query(
        r#"
        UPDATE workflow_approvals
        SET status = $3::approval_status,
            approver_pubkey = $4,
            note = $5,
            granted_at = CASE WHEN $3 = 'granted' THEN NOW() ELSE granted_at END,
            denied_at = CASE WHEN $3 = 'denied' THEN NOW() ELSE denied_at END
        WHERE community_id = $1 AND token = $2
        "#,
    )
    .bind(community.as_uuid())
    .bind(params.token_hash)
    .bind(new_status.to_string())
    .bind(params.approver_pubkey)
    .bind(params.note)
    .execute(tx.conn())
    .await?;

    let approver_hex = hex::encode(params.approver_pubkey);
    let resolution = serde_json::json!({
        "step_id": step_id,
        "status": if granted { "completed" } else { "denied" },
        "output": {
            "approved": granted,
            "approver": approver_hex,
            "note": params.note,
        },
    });
    let trace = resolve_gate_trace(&run.execution_trace, &step_id, resolution);
    if granted {
        sqlx::query(
            r#"
            UPDATE workflow_runs
            SET status = 'running',
                current_step = $3,
                execution_trace = $4,
                lease_owner = $5,
                lease_expires_at = NOW() + make_interval(secs => $6)
            WHERE community_id = $1 AND id = $2
            "#,
        )
        .bind(community.as_uuid())
        .bind(run_id)
        .bind(step_index + 1)
        .bind(&trace)
        .bind(params.resume_lease.owner)
        .bind(params.resume_lease.ttl_secs as f64)
        .execute(tx.conn())
        .await?;
    } else {
        let message = format!("workflow cancelled: approval denied by {approver_hex}");
        sqlx::query(
            r#"
            UPDATE workflow_runs
            SET status = 'cancelled',
                execution_trace = $3,
                error_code = 'approval_denied',
                error_message = $4,
                completed_at = NOW()
            WHERE community_id = $1 AND id = $2
            "#,
        )
        .bind(community.as_uuid())
        .bind(run_id)
        .bind(&trace)
        .bind(message)
        .execute(tx.conn())
        .await?;
    }
    let channel_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT channel_id FROM workflows WHERE community_id = $1 AND id = $2",
    )
    .bind(community.as_uuid())
    .bind(workflow_id)
    .fetch_one(tx.conn())
    .await?;
    let (decision_event, _) =
        crate::event::insert_event_in_transaction(tx, params.decision_event, channel_id).await?;
    Ok(ApprovalDecisionOutcome::Applied {
        run_id,
        workflow_id,
        decision_event: Box::new(decision_event),
    })
}

/// A pending approval whose deadline has passed.
#[derive(Debug, Clone)]
pub struct DueApproval {
    /// Owning community.
    pub community_id: CommunityId,
    /// Stored token hash.
    pub token_hash: Vec<u8>,
    /// Gated run.
    pub run_id: Uuid,
    /// Its workflow.
    pub workflow_id: Uuid,
    /// Gate step id.
    pub step_id: String,
    /// Workflow channel, if any.
    pub channel_id: Option<Uuid>,
}

/// Pending approvals past their deadline, across all communities.
pub async fn list_due_workflow_approvals(pool: &PgPool, limit: i64) -> Result<Vec<DueApproval>> {
    let rows = sqlx::query(
        r#"
        SELECT a.community_id, a.token, a.run_id, a.workflow_id, a.step_id, w.channel_id
        FROM workflow_approvals a
        JOIN workflows w ON w.community_id = a.community_id AND w.id = a.workflow_id
        WHERE a.status = 'pending' AND a.expires_at <= NOW()
        ORDER BY a.expires_at
        LIMIT $1
        "#,
    )
    .bind(limit.clamp(1, super::LIST_MAX_LIMIT))
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(DueApproval {
                community_id: CommunityId::from_uuid(row.try_get("community_id")?),
                token_hash: row.try_get("token")?,
                run_id: row.try_get("run_id")?,
                workflow_id: row.try_get("workflow_id")?,
                step_id: row.try_get("step_id")?,
                channel_id: row.try_get("channel_id")?,
            })
        })
        .collect()
}

/// Expire one due approval and fail its waiting run, atomically with the
/// relay-signed expiry notice. `None` when another sweeper got there first.
pub async fn expire_workflow_approval(
    db: &Db,
    due: &DueApproval,
    notice: &Event,
) -> Result<Option<StoredEvent>> {
    let mut tx = db.begin_event_write_transaction(due.community_id).await?;
    let affected = sqlx::query(
        r#"
        UPDATE workflow_approvals
        SET status = 'expired'
        WHERE community_id = $1 AND token = $2 AND status = 'pending' AND expires_at <= NOW()
        "#,
    )
    .bind(due.community_id.as_uuid())
    .bind(&due.token_hash)
    .execute(tx.conn())
    .await?
    .rows_affected();
    if affected != 1 {
        tx.rollback().await?;
        return Ok(None);
    }
    let trace: Option<Value> = sqlx::query_scalar(
        r#"
        SELECT execution_trace FROM workflow_runs
        WHERE community_id = $1 AND id = $2 AND status = 'waiting_approval'
        FOR UPDATE
        "#,
    )
    .bind(due.community_id.as_uuid())
    .bind(due.run_id)
    .fetch_optional(tx.conn())
    .await?;
    if let Some(trace) = trace {
        let trace = resolve_gate_trace(
            &trace,
            &due.step_id,
            serde_json::json!({ "step_id": due.step_id, "status": "expired" }),
        );
        sqlx::query(
            r#"
            UPDATE workflow_runs
            SET status = 'failed',
                execution_trace = $3,
                error_code = 'approval_expired',
                error_message = 'approval request expired without a decision',
                completed_at = NOW()
            WHERE community_id = $1 AND id = $2
            "#,
        )
        .bind(due.community_id.as_uuid())
        .bind(due.run_id)
        .bind(&trace)
        .execute(tx.conn())
        .await?;
    }
    let (stored, _) =
        crate::event::insert_event_in_transaction(&mut tx, notice, due.channel_id).await?;
    tx.commit().await?;
    Ok(Some(stored))
}

/// Running runs whose executor lease has lapsed, across all communities.
pub async fn list_abandoned_workflow_runs(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<(CommunityId, Uuid)>> {
    let rows = sqlx::query(
        r#"
        SELECT community_id, id FROM workflow_runs
        WHERE status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < NOW()
        ORDER BY lease_expires_at
        LIMIT $1
        "#,
    )
    .bind(limit.clamp(1, super::LIST_MAX_LIMIT))
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                CommunityId::from_uuid(row.try_get("community_id")?),
                row.try_get("id")?,
            ))
        })
        .collect()
}

/// Take over an abandoned run. `None` when it is no longer abandoned.
pub async fn claim_abandoned_workflow_run(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    lease: RunLease,
) -> Result<Option<WorkflowRunRecord>> {
    let row = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET lease_owner = $3, lease_expires_at = NOW() + make_interval(secs => $4)
        WHERE community_id = $1 AND id = $2 AND status = 'running'
          AND lease_expires_at IS NOT NULL AND lease_expires_at < NOW()
        RETURNING community_id, id, workflow_id, status::text AS status, trigger_event_id,
                  current_step, execution_trace, trigger_context, started_at, completed_at,
                  error_message, error_code, created_at
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(lease.owner)
    .bind(lease.ttl_secs as f64)
    .fetch_optional(pool)
    .await?;
    row.map(row_to_run_record).transpose()
}

impl Db {
    /// See [`claim_pending_workflow_run`].
    pub async fn claim_pending_workflow_run(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        lease: RunLease,
    ) -> Result<bool> {
        claim_pending_workflow_run(&self.pool, community_id, run_id, lease).await
    }

    /// See [`renew_workflow_run_lease`].
    pub async fn renew_workflow_run_lease(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        lease: RunLease,
    ) -> Result<bool> {
        renew_workflow_run_lease(&self.pool, community_id, run_id, lease).await
    }

    /// See [`checkpoint_workflow_run`].
    pub async fn checkpoint_workflow_run(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        owner: Uuid,
        current_step: i32,
        trace: &Value,
    ) -> Result<bool> {
        checkpoint_workflow_run(&self.pool, community_id, run_id, owner, current_step, trace).await
    }

    /// See [`settle_workflow_run`].
    #[allow(clippy::too_many_arguments)]
    pub async fn settle_workflow_run(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        owner: Uuid,
        status: RunStatus,
        current_step: i32,
        trace: &Value,
        failure: Option<WorkflowRunFailure<'_>>,
    ) -> Result<bool> {
        settle_workflow_run(
            &self.pool,
            community_id,
            run_id,
            owner,
            status,
            current_step,
            trace,
            failure,
        )
        .await
    }

    /// See [`list_due_workflow_approvals`].
    pub async fn list_due_workflow_approvals(&self, limit: i64) -> Result<Vec<DueApproval>> {
        list_due_workflow_approvals(&self.pool, limit).await
    }

    /// See [`list_abandoned_workflow_runs`].
    pub async fn list_abandoned_workflow_runs(
        &self,
        limit: i64,
    ) -> Result<Vec<(CommunityId, Uuid)>> {
        list_abandoned_workflow_runs(&self.pool, limit).await
    }

    /// See [`claim_abandoned_workflow_run`].
    pub async fn claim_abandoned_workflow_run(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        lease: RunLease,
    ) -> Result<Option<WorkflowRunRecord>> {
        claim_abandoned_workflow_run(&self.pool, community_id, run_id, lease).await
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_gate_trace;
    use serde_json::json;

    #[test]
    fn gate_resolution_replaces_only_the_waiting_entry() {
        let trace = json!([
            { "step_id": "gate", "status": "completed" },
            { "step_id": "before", "status": "completed" },
            { "step_id": "gate", "status": "waiting_approval" }
        ]);
        let resolved = resolve_gate_trace(
            &trace,
            "gate",
            json!({ "step_id": "gate", "status": "completed", "output": { "approved": true } }),
        );
        assert_eq!(
            resolved,
            json!([
                { "step_id": "gate", "status": "completed" },
                { "step_id": "before", "status": "completed" },
                { "step_id": "gate", "status": "completed", "output": { "approved": true } }
            ])
        );
    }

    #[test]
    fn gate_resolution_appends_when_no_waiting_entry_exists() {
        let resolved = resolve_gate_trace(&json!([]), "gate", json!({ "step_id": "gate" }));
        assert_eq!(resolved, json!([{ "step_id": "gate" }]));
    }
}
