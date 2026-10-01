ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'TECHNICIAN';
ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'CUSTOMER_ADMIN';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON users(tenant_id);

ALTER TABLE webhook_configs
    ADD COLUMN IF NOT EXISTS provider VARCHAR(30) NOT NULL DEFAULT 'generic';
ALTER TABLE webhook_configs
    ADD COLUMN IF NOT EXISTS auth_header VARCHAR(100);
ALTER TABLE webhook_configs
    ADD COLUMN IF NOT EXISTS auth_value VARCHAR(512);

CREATE TABLE IF NOT EXISTS psa_alert_states (
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    hostname VARCHAR(100) NOT NULL,
    module_name VARCHAR(50) NOT NULL,
    failing_since TIMESTAMP WITH TIME ZONE,
    ticket_created_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (tenant_id, hostname, module_name)
);