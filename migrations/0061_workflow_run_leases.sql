-- Durable ownership of in-flight workflow execution.
--
-- A run is executed by exactly one relay process at a time. The owner holds a
-- renewable lease; when a process dies (crash, SIGKILL, pod eviction) its lease
-- expires and another process claims the run and resumes it from the last
-- persisted step checkpoint. Suspended (waiting_approval) and terminal runs
-- hold no lease.
ALTER TABLE workflow_runs ADD COLUMN lease_owner UUID;
ALTER TABLE workflow_runs ADD COLUMN lease_expires_at TIMESTAMPTZ;
ALTER TABLE workflow_runs ADD CONSTRAINT workflow_runs_lease_pair
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL));

-- Global recovery scans (all communities) for abandoned running runs.
CREATE INDEX idx_workflow_runs_lease_expiry
    ON workflow_runs (lease_expires_at)
    WHERE status = 'running' AND lease_expires_at IS NOT NULL;

-- Global expiry scans for pending approval gates.
CREATE INDEX idx_workflow_approvals_pending_expiry
    ON workflow_approvals (expires_at)
    WHERE status = 'pending';
