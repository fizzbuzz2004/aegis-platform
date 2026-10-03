BEGIN;

ALTER TABLE host_devices
    ADD COLUMN IF NOT EXISTS client_cert_fingerprint VARCHAR(64);
ALTER TABLE host_devices
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS ix_host_devices_client_cert_fingerprint
    ON host_devices (client_cert_fingerprint)
    WHERE client_cert_fingerprint IS NOT NULL;

COMMENT ON COLUMN host_devices.client_cert_fingerprint IS
    'Lowercase SHA-256 fingerprint of the verified agent leaf certificate. Existing NULL rows require re-enrollment.';

COMMIT;
