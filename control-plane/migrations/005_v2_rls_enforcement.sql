-- control-plane/migrations/005_v2_rls_enforcement.sql
ALTER TABLE aegis_v2.scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_v2.scan_runs FORCE ROW LEVEL SECURITY;

ALTER TABLE aegis_v2.scan_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_v2.scan_findings FORCE ROW LEVEL SECURITY;

-- Mandantensichere RLS Policy
CREATE POLICY tenant_isolation_policy ON aegis_v2.scan_runs
    USING (
        msp_id = aegis_v2.current_msp_id() 
        AND (aegis_v2.current_customer_id() IS NULL OR customer_id = aegis_v2.current_customer_id())
    )
    WITH CHECK (
        msp_id = aegis_v2.current_msp_id() 
        AND customer_id = aegis_v2.current_customer_id()
    );
