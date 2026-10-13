//! Run orchestration: claim, lease renewal, checkpointed execution,
//! settlement, approval suspension and crash recovery.
//!
//! Every path that executes steps first owns the run through a database lease
//! (see `buzz_db::workflow::RunLease`). Settlement and suspension are
//! compare-and-set against that lease, so a stale executor can never overwrite
//! the state written by the executor that replaced it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use buzz_core::tenant::CommunityId;
use buzz_db::workflow::{ApprovalSuspension, RunLease, RunStatus, WorkflowRunFailure};
use chrono::Utc;
use nostr::Tag;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use crate::error::{PartialProgress, WorkflowError};
use crate::executor::{
    execute_steps, ApprovalRequest, ExecutionResult, LeaseHandle, RunCursor, TriggerContext,
};
use crate::schema::WorkflowDef;
use crate::WorkflowEngine;

/// Lifetime of an executor lease; a crashed executor's runs are reclaimed
/// at most this long after its last renewal.
pub const LEASE_TTL_SECS: i64 = 15;
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(5);
const RECOVERY_INTERVAL: Duration = Duration::from_secs(2);
const RECOVERY_BATCH: i64 = 50;

/// Kind of the relay-signed approval request.
const KIND_APPROVAL_REQUESTED: u16 = buzz_core::kind::KIND_WORKFLOW_APPROVAL_REQUESTED as u16;
/// Kind of the relay-signed denial/expiry notice.
const KIND_APPROVAL_DENIED: u16 = buzz_core::kind::KIND_WORKFLOW_APPROVAL_DENIED as u16;

fn tag(parts: &[&str]) -> Result<Tag, WorkflowError> {
    Tag::parse(parts.iter().copied())
        .map_err(|e| WorkflowError::InvalidDefinition(format!("event tag: {e}")))
}

/// Hex SHA-256 of a raw approval token: the public approval reference used in
/// `d` tags and decision events.
pub fn approval_reference(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl WorkflowEngine {
    /// Lease this engine instance uses for runs it executes.
    pub fn run_lease(&self) -> RunLease {
        RunLease {
            owner: self.instance_id,
            ttl_secs: LEASE_TTL_SECS,
        }
    }

    /// Claim a freshly created `pending` run and execute it in the background.
    pub fn spawn_run(
        self: &Arc<Self>,
        community_id: CommunityId,
        run_id: Uuid,
        def: WorkflowDef,
        trigger_ctx: TriggerContext,
    ) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = engine
                .execute_pending_run(community_id, run_id, &def, &trigger_ctx)
                .await
            {
                tracing::debug!(run_id = %run_id, "workflow run ended without completing: {error}");
            }
        });
    }

    /// Claim a `pending` run and execute it to suspension or settlement.
    ///
    /// Fails fast with [`WorkflowError::CapacityExceeded`] (and marks the run
    /// failed) when every concurrency permit is taken.
    pub async fn execute_pending_run(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        def: &WorkflowDef,
        trigger_ctx: &TriggerContext,
    ) -> Result<ExecutionResult, WorkflowError> {
        let Ok(permit) = Arc::clone(&self.run_semaphore).try_acquire_owned() else {
            let error = WorkflowError::CapacityExceeded;
            self.db
                .update_workflow_run(
                    community_id,
                    run_id,
                    RunStatus::Failed,
                    0,
                    &Value::Array(Vec::new()),
                    Some(WorkflowRunFailure {
                        code: error.code(),
                        message: &error.to_string(),
                    }),
                )
                .await?;
            return Err(error);
        };
        if !self
            .db
            .claim_pending_workflow_run(community_id, run_id, self.run_lease())
            .await?
        {
            return Err(WorkflowError::LeaseLost);
        }
        self.drive_claimed(
            community_id,
            run_id,
            def,
            trigger_ctx,
            RunCursor::default(),
            permit,
        )
        .await
    }

    /// Resume a run whose lease this engine already holds, e.g. right after a
    /// granted approval was committed with this engine as the lease owner.
    pub fn spawn_resume(self: &Arc<Self>, community_id: CommunityId, run_id: Uuid) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = engine.resume_held_run(community_id, run_id).await {
                tracing::warn!(run_id = %run_id, "workflow resume ended without completing: {error}");
            }
        });
    }

    async fn resume_held_run(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
    ) -> Result<ExecutionResult, WorkflowError> {
        let permit = Arc::clone(&self.run_semaphore)
            .acquire_owned()
            .await
            .map_err(|_| WorkflowError::CapacityExceeded)?;
        let run = self.db.get_workflow_run(community_id, run_id).await?;
        let workflow = self.db.get_workflow(community_id, run.workflow_id).await?;
        let lease = LeaseHandle {
            owner: self.instance_id,
            lost: Arc::new(AtomicBool::new(false)),
        };
        let def: WorkflowDef = match serde_json::from_value(workflow.definition.clone()) {
            Ok(def) => def,
            Err(e) => {
                let error = WorkflowError::InvalidDefinition(format!("stored definition: {e}"));
                return self
                    .settle(
                        community_id,
                        run_id,
                        &lease,
                        Err((
                            error,
                            PartialProgress {
                                step_index: run.current_step.max(0) as usize,
                                trace: run.execution_trace.as_array().cloned().unwrap_or_default(),
                            },
                        )),
                    )
                    .await;
            }
        };
        // SEC-006: a resumed run acts with the owner's authority as of now,
        // not as of when it was suspended or abandoned.
        if let Some(channel_id) = workflow.channel_id {
            if let Err(error) = self
                .check_owner_authority(community_id, channel_id, &workflow.owner_pubkey, &def)
                .await
            {
                return self
                    .settle(
                        community_id,
                        run_id,
                        &lease,
                        Err((
                            error,
                            PartialProgress {
                                step_index: run.current_step.max(0) as usize,
                                trace: run.execution_trace.as_array().cloned().unwrap_or_default(),
                            },
                        )),
                    )
                    .await;
            }
        }
        let trigger_ctx: TriggerContext = run
            .trigger_context
            .as_ref()
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_default();
        let cursor = RunCursor::from_checkpoint(run.current_step, &run.execution_trace);
        self.drive_claimed(community_id, run_id, &def, &trigger_ctx, cursor, permit)
            .await
    }

    async fn drive_claimed(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        def: &WorkflowDef,
        trigger_ctx: &TriggerContext,
        cursor: RunCursor,
        _permit: OwnedSemaphorePermit,
    ) -> Result<ExecutionResult, WorkflowError> {
        let lease = LeaseHandle {
            owner: self.instance_id,
            lost: Arc::new(AtomicBool::new(false)),
        };
        let renewal = {
            let db = self.db.clone();
            let lost = Arc::clone(&lease.lost);
            let run_lease = self.run_lease();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(LEASE_RENEW_INTERVAL).await;
                    match db
                        .renew_workflow_run_lease(community_id, run_id, run_lease)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            lost.store(true, Ordering::SeqCst);
                            break;
                        }
                        // A transient failure is retried; if ownership really
                        // lapsed, the next checkpoint observes it.
                        Err(e) => tracing::warn!(run_id = %run_id, "lease renewal failed: {e}"),
                    }
                }
            })
        };
        let result = execute_steps(
            self,
            community_id,
            run_id,
            def,
            trigger_ctx,
            cursor,
            Some(&lease),
        )
        .await;
        renewal.abort();
        self.settle(community_id, run_id, &lease, result).await
    }

    async fn settle(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        lease: &LeaseHandle,
        result: Result<ExecutionResult, (WorkflowError, PartialProgress)>,
    ) -> Result<ExecutionResult, WorkflowError> {
        match result {
            Ok(result) => match result.suspension.clone() {
                Some(request) => {
                    if let Err(error) = self
                        .suspend(community_id, run_id, lease, &result, &request)
                        .await
                    {
                        if matches!(error, WorkflowError::LeaseLost) {
                            return Err(error);
                        }
                        self.settle_failure(
                            community_id,
                            run_id,
                            lease,
                            &error,
                            result.step_index,
                            result.trace,
                        )
                        .await?;
                        return Err(error);
                    }
                    Ok(result)
                }
                None => {
                    let settled = self
                        .db
                        .settle_workflow_run(
                            community_id,
                            run_id,
                            lease.owner,
                            RunStatus::Completed,
                            i32::try_from(result.step_index).unwrap_or(i32::MAX),
                            &Value::Array(result.trace.clone()),
                            None,
                        )
                        .await?;
                    if !settled {
                        return Err(WorkflowError::LeaseLost);
                    }
                    tracing::info!(run_id = %run_id, "Workflow run completed");
                    Ok(result)
                }
            },
            Err((WorkflowError::LeaseLost, _)) => {
                tracing::info!(run_id = %run_id, "Workflow run lease lost; another owner continues it");
                Err(WorkflowError::LeaseLost)
            }
            Err((error, progress)) => {
                tracing::warn!(run_id = %run_id, "Workflow run failed: {error}");
                self.settle_failure(
                    community_id,
                    run_id,
                    lease,
                    &error,
                    progress.step_index,
                    progress.trace,
                )
                .await?;
                Err(error)
            }
        }
    }

    async fn settle_failure(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        lease: &LeaseHandle,
        error: &WorkflowError,
        step_index: usize,
        trace: Vec<Value>,
    ) -> Result<(), WorkflowError> {
        self.db
            .settle_workflow_run(
                community_id,
                run_id,
                lease.owner,
                RunStatus::Failed,
                i32::try_from(step_index).unwrap_or(i32::MAX),
                &Value::Array(trace),
                Some(WorkflowRunFailure {
                    code: error.code(),
                    message: &error.to_string(),
                }),
            )
            .await?;
        Ok(())
    }

    async fn suspend(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        lease: &LeaseHandle,
        result: &ExecutionResult,
        request: &ApprovalRequest,
    ) -> Result<(), WorkflowError> {
        let run = self.db.get_workflow_run(community_id, run_id).await?;
        let workflow = self.db.get_workflow(community_id, run.workflow_id).await?;
        let channel_id = workflow.channel_id.ok_or_else(|| {
            WorkflowError::InvalidDefinition(
                "request_approval requires a channel-scoped workflow".into(),
            )
        })?;
        let expires_at = Utc::now()
            + chrono::Duration::seconds(i64::try_from(request.timeout_secs).unwrap_or(i64::MAX));
        let reference = approval_reference(&request.token);
        let owner_hex = hex::encode(&workflow.owner_pubkey);

        let mut trace = result.trace.clone();
        trace.push(serde_json::json!({
            "step_id": request.step_id,
            "status": "waiting_approval",
            "output": {
                "approval_ref": reference,
                "approver": request.approver_spec,
                "expires_at": expires_at.timestamp(),
            },
        }));

        let channel = channel_id.to_string();
        let mut tags = vec![
            tag(&["h", &channel])?,
            tag(&["d", &reference])?,
            tag(&["buzz:workflow", "true"])?,
            tag(&["buzz:workflow-owner", &owner_hex])?,
        ];
        if request.approver_spec != "any" {
            tags.push(tag(&["p", &request.approver_spec])?);
        }
        let content = serde_json::json!({
            "summary": request.message,
            "workflow_id": run.workflow_id,
            "run_id": run_id,
            "step_id": request.step_id,
            "approver": request.approver_spec,
            "expires_at": expires_at.timestamp(),
        })
        .to_string();
        let sink = self.action_sink()?;
        let event = sink.sign_event(KIND_APPROVAL_REQUESTED, &content, tags)?;
        let stored = buzz_db::workflow::suspend_workflow_run_for_approval(
            &self.db,
            ApprovalSuspension {
                community_id,
                run_id,
                owner: lease.owner,
                workflow_id: run.workflow_id,
                channel_id,
                token: &request.token,
                step_id: &request.step_id,
                step_index: i32::try_from(request.step_index).unwrap_or(i32::MAX),
                approver_spec: &request.approver_spec,
                expires_at,
                trace: &Value::Array(trace),
                request_event: &event,
            },
        )
        .await?
        .ok_or(WorkflowError::LeaseLost)?;
        tracing::info!(run_id = %run_id, step = %request.step_id, "Workflow run waiting for approval");
        sink.publish_stored(community_id, stored).await;
        Ok(())
    }

    /// Background loop: expire overdue approval gates and take over runs whose
    /// executor lease lapsed. Runs one pass immediately so a restarted relay
    /// recovers without waiting a full interval.
    pub async fn run_recovery(self: &Arc<Self>) {
        tracing::info!("WorkflowEngine recovery loop started");
        loop {
            self.recover_once().await;
            tokio::time::sleep(RECOVERY_INTERVAL).await;
        }
    }

    /// One recovery pass. Errors are logged and retried on the next pass.
    pub async fn recover_once(self: &Arc<Self>) {
        if let Err(e) = self.expire_due_approvals().await {
            tracing::warn!("workflow approval expiry pass failed: {e}");
        }
        match self.db.list_abandoned_workflow_runs(RECOVERY_BATCH).await {
            Ok(abandoned) => {
                for (community_id, run_id) in abandoned {
                    match self
                        .db
                        .claim_abandoned_workflow_run(community_id, run_id, self.run_lease())
                        .await
                    {
                        Ok(Some(_)) => {
                            tracing::info!(run_id = %run_id, "Recovering abandoned workflow run");
                            self.spawn_resume(community_id, run_id);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(run_id = %run_id, "claim abandoned run failed: {e}")
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("abandoned workflow run scan failed: {e}"),
        }
    }

    async fn expire_due_approvals(&self) -> Result<(), WorkflowError> {
        let due = self.db.list_due_workflow_approvals(RECOVERY_BATCH).await?;
        if due.is_empty() {
            return Ok(());
        }
        let sink = self.action_sink()?;
        for approval in due {
            let reference = hex::encode(&approval.token_hash);
            let mut tags = vec![tag(&["d", &reference])?, tag(&["status", "expired"])?];
            if let Some(channel_id) = approval.channel_id {
                tags.push(tag(&["h", &channel_id.to_string()])?);
            }
            let content = serde_json::json!({
                "status": "expired",
                "workflow_id": approval.workflow_id,
                "run_id": approval.run_id,
            })
            .to_string();
            let notice = sink.sign_event(KIND_APPROVAL_DENIED, &content, tags)?;
            match buzz_db::workflow::expire_workflow_approval(&self.db, &approval, &notice).await {
                Ok(Some(stored)) => {
                    tracing::info!(run_id = %approval.run_id, "Workflow approval expired");
                    sink.publish_stored(approval.community_id, stored).await;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(run_id = %approval.run_id, "approval expiry failed: {e}"),
            }
        }
        Ok(())
    }
}
