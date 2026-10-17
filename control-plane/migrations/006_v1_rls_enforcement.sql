-- Aktivierung von Row-Level Security auf den V1-Tabellen
ALTER TABLE host_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_devices FORCE ROW LEVEL SECURITY;

ALTER TABLE module_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE module_results FORCE ROW LEVEL SECURITY;

ALTER TABLE webhook_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_configs FORCE ROW LEVEL SECURITY;

-- Funktion zum Auslesen des aktuellen V1 Tenant-Kontexts aus der Session
CREATE OR REPLACE FUNCTION public.current_tenant_id() RETURNS integer
LANGUAGE sql STABLE
AS $$ 
    SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::integer 
$$;

-- RLS-Policy für Host-Devices
CREATE POLICY v1_host_devices_isolation_policy ON host_devices
    USING (
        public.current_tenant_id() IS NULL 
        OR tenant_id = public.current_tenant_id()
    )
    WITH CHECK (
        tenant_id = public.current_tenant_id()
    );

-- RLS-Policy für Module-Results
CREATE POLICY v1_module_results_isolation_policy ON module_results
    USING (
        public.current_tenant_id() IS NULL 
        OR tenant_id = public.current_tenant_id()
    )
    WITH CHECK (
        tenant_id = public.current_tenant_id()
    );

-- RLS-Policy für Webhook-Configs
CREATE POLICY v1_webhook_configs_isolation_policy ON webhook_configs
    USING (
        public.current_tenant_id() IS NULL 
        OR tenant_id = public.current_tenant_id()
    )
    WITH CHECK (
        tenant_id = public.current_tenant_id()
    );
