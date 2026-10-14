-- ── Workflow runs ─────────────────────────────────────────────────────────────

CREATE TABLE workflow_runs (
    community_id        UUID NOT NULL REFERENCES communities(id),
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    workflow_id         UUID NOT NULL,
    status              run_status NOT NULL DEFAULT 'pending',
    trigger_event_id    BYTEA,
    current_step        INT NOT NULL DEFAULT 0,
    execution_trace     JSONB NOT NULL DEFAULT '[]',
    trigger_context     JSONB,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    error_message       TEXT,
    error_code          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_owner         UUID,
    lease_expires_at    TIMESTAMPTZ,
    PRIMARY KEY (community_id, id),
    FOREIGN KEY (community_id, workflow_id)
        REFERENCES workflows (community_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_runs_lease_pair
        CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);

CREATE INDEX idx_workflow_runs_workflow ON workflow_runs (community_id, workflow_id);
CREATE INDEX idx_workflow_runs_status ON workflow_runs (community_id, status);
CREATE INDEX idx_workflow_runs_lease_expiry ON workflow_runs (lease_expires_at)
    WHERE status = 'running' AND lease_expires_at IS NOT NULL;
