BEGIN;

CREATE SCHEMA IF NOT EXISTS aegis_v2;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        CREATE ROLE aegis_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
END
$$;
ALTER ROLE aegis_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

CREATE TABLE aegis_v2.msps (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    UNIQUE (msp_id, customer_id),
    CHECK (id = msp_id)
);

CREATE TABLE aegis_v2.customers (
    msp_id uuid NOT NULL REFERENCES aegis_v2.msps(id),
    id uuid NOT NULL,
    customer_id uuid NOT NULL,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (msp_id, id),
    UNIQUE (msp_id, customer_id),
    CHECK (id = customer_id)
);

CREATE TABLE aegis_v2.principal_memberships (
    id uuid PRIMARY KEY,
    principal_id uuid NOT NULL,
    msp_id uuid NOT NULL REFERENCES aegis_v2.msps(id),
    customer_id uuid NULL,
    role text NOT NULL CHECK (role IN ('MSP_ADMIN', 'TECHNICIAN', 'CUSTOMER_ADMIN', 'AGENT')),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id),
    CHECK (customer_id IS NULL OR customer_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE UNIQUE INDEX principal_memberships_msp_scope_uq
    ON aegis_v2.principal_memberships (principal_id, msp_id)
    WHERE customer_id IS NULL;
CREATE UNIQUE INDEX principal_memberships_customer_scope_uq
    ON aegis_v2.principal_memberships (principal_id, msp_id, customer_id)
    WHERE customer_id IS NOT NULL;
CREATE INDEX principal_memberships_lookup_idx
    ON aegis_v2.principal_memberships (principal_id, msp_id, customer_id);

CREATE TABLE aegis_v2.scan_runs (
    id uuid PRIMARY KEY,
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    started_at timestamptz NOT NULL,
    evaluated_at timestamptz,
    data_as_of timestamptz,
    rule_pack_id text NOT NULL,
    rule_pack_digest text NOT NULL,
    status text NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'failed')),
    UNIQUE (msp_id, customer_id, id),
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id)
);
CREATE INDEX scan_runs_tenant_time
    ON aegis_v2.scan_runs (msp_id, customer_id, started_at DESC);

CREATE TABLE aegis_v2.scan_findings (
    id uuid PRIMARY KEY,
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    scan_run_id uuid NOT NULL,
    rule_id text NOT NULL,
    status text NOT NULL,
    severity text NOT NULL,
    evidence_digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id),
    FOREIGN KEY (msp_id, customer_id, scan_run_id)
        REFERENCES aegis_v2.scan_runs (msp_id, customer_id, id)
);
CREATE INDEX scan_findings_scan_idx
    ON aegis_v2.scan_findings (msp_id, customer_id, scan_run_id);

CREATE TABLE aegis_v2.evidence_chain_heads (
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    sequence_number bigint NOT NULL DEFAULT 0,
    head_hash bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (msp_id, customer_id),
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id),
    CHECK (octet_length(head_hash) = 32)
);

CREATE TABLE aegis_v2.evidence_events (
    id uuid PRIMARY KEY,
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    sequence_number bigint NOT NULL,
    previous_hash bytea NOT NULL,
    event_hash bytea NOT NULL,
    canonical_event bytea NOT NULL,
    pseudonymous_subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (msp_id, customer_id, sequence_number),
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id),
    CHECK (octet_length(previous_hash) = 32),
    CHECK (octet_length(event_hash) = 32)
);

CREATE TABLE aegis_v2.evidence_anchor_manifests (
    id uuid PRIMARY KEY,
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    first_sequence bigint NOT NULL,
    last_sequence bigint NOT NULL,
    merkle_root bytea NOT NULL,
    kms_key_arn text NOT NULL,
    signature bytea NOT NULL,
    object_key text NOT NULL,
    anchored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id),
    CHECK (first_sequence > 0 AND last_sequence >= first_sequence),
    CHECK (octet_length(merkle_root) = 32)
);

CREATE TABLE aegis_v2.report_jobs (
    id uuid PRIMARY KEY,
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    evaluated_at timestamptz NOT NULL,
    data_as_of timestamptz NOT NULL,
    rule_pack_digest text NOT NULL,
    status text NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'failed')),
    object_key text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id),
    FOREIGN KEY (msp_id, customer_id, snapshot_id)
        REFERENCES aegis_v2.scan_runs (msp_id, customer_id, id)
);

CREATE TABLE aegis_v2.outbox_events (
    id uuid PRIMARY KEY,
    msp_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (msp_id, customer_id) REFERENCES aegis_v2.customers (msp_id, id)
);
CREATE INDEX outbox_unpublished_idx
    ON aegis_v2.outbox_events (available_at, created_at)
    WHERE published_at IS NULL;

CREATE FUNCTION aegis_v2.current_user_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;
CREATE FUNCTION aegis_v2.current_msp_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT NULLIF(current_setting('app.msp_id', true), '')::uuid $$;
CREATE FUNCTION aegis_v2.current_customer_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT NULLIF(current_setting('app.customer_id', true), '')::uuid $$;

CREATE FUNCTION aegis_v2.can_access_customer(target_msp_id uuid, target_customer_id uuid)
RETURNS boolean
LANGUAGE sql STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM aegis_v2.principal_memberships AS membership
        WHERE membership.principal_id = aegis_v2.current_user_id()
          AND membership.msp_id = target_msp_id
          AND (membership.customer_id IS NULL OR membership.customer_id = target_customer_id)
    )
$$;

CREATE FUNCTION aegis_v2.reject_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'evidence_events is append-only';
END
$$;
CREATE TRIGGER evidence_events_append_only
    BEFORE UPDATE OR DELETE ON aegis_v2.evidence_events
    FOR EACH ROW EXECUTE FUNCTION aegis_v2.reject_evidence_mutation();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'msps', 'customers', 'principal_memberships', 'scan_runs', 'scan_findings',
        'evidence_chain_heads', 'evidence_events', 'evidence_anchor_manifests',
        'report_jobs', 'outbox_events'
    ] LOOP
        EXECUTE format('ALTER TABLE aegis_v2.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE aegis_v2.%I FORCE ROW LEVEL SECURITY', table_name);
    END LOOP;
END
$$;

CREATE POLICY msp_scope_policy ON aegis_v2.msps
    USING (
        id = aegis_v2.current_msp_id()
        AND EXISTS (
            SELECT 1
            FROM aegis_v2.principal_memberships AS membership
            WHERE membership.principal_id = aegis_v2.current_user_id()
              AND membership.msp_id = msps.id
              AND membership.customer_id IS NULL
        )
    );
CREATE POLICY customer_scope_policy ON aegis_v2.customers
    USING (msp_id = aegis_v2.current_msp_id()
           AND (aegis_v2.current_customer_id() IS NULL OR id = aegis_v2.current_customer_id())
           AND aegis_v2.can_access_customer(msp_id, id));
CREATE POLICY membership_self_read_policy ON aegis_v2.principal_memberships
    FOR SELECT
    USING (principal_id = aegis_v2.current_user_id()
           AND msp_id = aegis_v2.current_msp_id()
           AND (aegis_v2.current_customer_id() IS NULL
                OR customer_id IS NULL
                OR customer_id = aegis_v2.current_customer_id()));

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'scan_runs', 'scan_findings', 'evidence_chain_heads', 'evidence_events',
        'evidence_anchor_manifests', 'report_jobs', 'outbox_events'
    ] LOOP
        EXECUTE format(
            'CREATE POLICY tenant_scope_policy ON aegis_v2.%I USING '
            '(msp_id = aegis_v2.current_msp_id() '
            'AND (aegis_v2.current_customer_id() IS NULL OR customer_id = aegis_v2.current_customer_id()) '
            'AND aegis_v2.can_access_customer(msp_id, customer_id)) '
            'WITH CHECK (msp_id = aegis_v2.current_msp_id() '
            'AND customer_id = aegis_v2.current_customer_id() '
            'AND aegis_v2.can_access_customer(msp_id, customer_id))',
            table_name
        );
    END LOOP;
END
$$;

REVOKE ALL ON SCHEMA aegis_v2 FROM PUBLIC;
GRANT USAGE ON SCHEMA aegis_v2 TO aegis_app;
REVOKE ALL ON ALL TABLES IN SCHEMA aegis_v2 FROM PUBLIC;
GRANT SELECT ON aegis_v2.msps, aegis_v2.customers, aegis_v2.principal_memberships TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON aegis_v2.scan_runs, aegis_v2.scan_findings,
    aegis_v2.evidence_chain_heads, aegis_v2.report_jobs, aegis_v2.outbox_events TO aegis_app;
GRANT SELECT, INSERT ON aegis_v2.evidence_events, aegis_v2.evidence_anchor_manifests TO aegis_app;
GRANT EXECUTE ON FUNCTION aegis_v2.current_user_id(),
    aegis_v2.current_msp_id(), aegis_v2.current_customer_id(),
    aegis_v2.can_access_customer(uuid, uuid) TO aegis_app;

COMMIT;
