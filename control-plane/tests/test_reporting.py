import asyncio
import json
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.admin import TenantCreateSchema, TenantResponseSchema, create_tenant, toggle_module
from app.api.v1.reporting import (
    generate_host_compliance_report,
    generate_monthly_compliance_report,
    generate_tenant_compliance_report,
)
from app.core.database import Base
from app.main import app
from app.models.module_state import ToggleRequest
from app.models.orm import HostDevice, ModuleResult, Tenant, TenantModule, User, UserRole


def make_test_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return engine, Session(engine)


def test_monthly_pdf_route_is_mounted():
    assert any(route.path == "/api/v1/reports/tenant/{tenant_id}/monthly-pdf" for route in app.routes)


def test_tenant_and_host_a4_pdf_routes_are_mounted():
    paths = {route.path for route in app.routes}
    assert "/api/v1/reports/tenant/{tenant_id}/pdf" in paths
    assert "/api/v1/reports/tenant/{tenant_id}/host/{hostname}/pdf" in paths


def test_tenant_and_host_reports_generate_downloadable_a4_pdfs():
    engine, db = make_test_session()
    try:
        tenant = Tenant(
            name="Systemhaus Test",
            enrollment_code="test-enrollment-a4",
            brand_color_hex="#257568",
            custom_footer="Vertraulich",
        )
        user = User(username="report-a4-tech", hashed_password="unused", role=UserRole.TECHNICIAN)
        db.add_all([tenant, user])
        db.flush()
        host = HostDevice(
            tenant_id=tenant.id,
            hostname="windows-11",
            os_info="windows-amd64",
            host_token="test-host-token",
        )
        db.add(host)
        db.add_all([
            ModuleResult(
                tenant_id=tenant.id,
                hostname=host.hostname,
                module_name="firewall_status",
                findings=json.dumps([
                    {"status": "PASS", "code": "FW_ACTIVE", "severity": "INFO", "message": "Firewall aktiv", "compliance": ["NIS2:Art21.2.e"]},
                    {"status": "FAIL", "code": "BACKUP_MISSING", "severity": "HIGH", "message": "Backup fehlt", "compliance": ["ISO27001:A.8.13"]},
                ]),
                timestamp=datetime.now(timezone.utc),
            ),
            ModuleResult(
                tenant_id=tenant.id,
                hostname=host.hostname,
                module_name="worm_audit",
                findings=json.dumps([
                    {"status": "PASS", "code": "WORM_INTEGRITY_CHECK", "severity": "INFO", "message": "Integrität bestätigt", "compliance": ["NIS2:Art21.2.j"]},
                ]),
                timestamp=datetime.now(timezone.utc),
            ),
        ])
        db.commit()

        tenant_response = generate_tenant_compliance_report(tenant.id, user, db)
        host_response = generate_host_compliance_report(tenant.id, host.hostname, user, db)

        async def response_bytes(response):
            return b"".join([chunk async for chunk in response.body_iterator])

        tenant_pdf = asyncio.run(response_bytes(tenant_response))
        host_pdf = asyncio.run(response_bytes(host_response))
        assert tenant_response.media_type == "application/pdf"
        assert tenant_pdf.startswith(b"%PDF-")
        assert b"/MediaBox [ 0 0 595.2756 841.8898 ]" in tenant_pdf
        assert 'filename="Compliance_Report_Systemhaus_Test_A4.pdf"' in tenant_response.headers["content-disposition"]
        assert host_response.media_type == "application/pdf"
        assert host_pdf.startswith(b"%PDF-")
        assert 'filename="Compliance_Report_Systemhaus_Test_windows-11_A4.pdf"' in host_response.headers["content-disposition"]
        with pytest.raises(HTTPException) as not_found:
            generate_host_compliance_report(tenant.id, "missing-host", user, db)
        assert not_found.value.status_code == 404

        customer_user = User(
            username="report-a4-customer",
            hashed_password="unused",
            role=UserRole.CUSTOMER_ADMIN,
            tenant_id=tenant.id + 1,
        )
        with pytest.raises(HTTPException) as forbidden:
            generate_tenant_compliance_report(tenant.id, customer_user, db)
        assert forbidden.value.status_code == 403
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_monthly_pdf_generates_with_invalid_logo_fallback():
    engine, db = make_test_session()
    try:
        tenant = Tenant(
            name="Systemhaus Test",
            enrollment_code="test-enrollment",
            logo_base64="not-valid-base64",
            brand_color_hex="#257568",
            custom_footer="Interner Audit-Bericht",
        )
        db.add(tenant)
        db.flush()
        db.add(ModuleResult(
            tenant_id=tenant.id,
            hostname="client-01",
            module_name="firewall_status",
            findings=json.dumps([
                {"status": "PASS", "code": "FW_ACTIVE", "severity": "INFO", "message": "Firewall aktiv", "compliance": ["NIS2:Art21.2.e"]},
                {"status": "FAIL", "code": "BACKUP_MISSING", "severity": "HIGH", "message": "Backup fehlt", "compliance": ["ISO27001:A.8.13"]},
            ]),
            timestamp=datetime.now(timezone.utc),
        ))
        db.commit()

        technician = User(username="report-tech", hashed_password="unused", role=UserRole.TECHNICIAN)
        response = generate_monthly_compliance_report(tenant.id, technician, db)

        async def response_bytes():
            return b"".join([chunk async for chunk in response.body_iterator])

        pdf = asyncio.run(response_bytes())
        assert response.media_type == "application/pdf"
        assert pdf.startswith(b"%PDF-")
        assert "Systemhaus_Test" in response.headers["content-disposition"]
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_tenant_accepts_arbitrary_module_names():
    engine, db = make_test_session()
    try:
        tenant = Tenant(name="Module Test", enrollment_code="module-test-enrollment")
        db.add(tenant)
        db.commit()

        response = toggle_module(
            ToggleRequest(tenant_id=tenant.id, module_name="custom_probe_v2", enable=True),
            object(),
            db,
        )

        assert response["status"] == "success"
        assert db.query(TenantModule).filter_by(
            tenant_id=tenant.id,
            module_name="custom_probe_v2",
        ).one().is_enabled
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_tenant_create_response_includes_branding_fields():
    engine, db = make_test_session()
    try:
        tenant = create_tenant(
            TenantCreateSchema(
                name="Brand Systemhaus",
                logo_base64="cG5nLWJhc2U2NA==",
                brand_color_hex="#35687a",
                custom_footer="Vertraulich",
            ),
            object(),
            db,
        )
        response = TenantResponseSchema.model_validate(tenant)
        assert response.logo_base64 == "cG5nLWJhc2U2NA=="
        assert response.brand_color_hex == "#35687a"
        assert response.custom_footer == "Vertraulich"
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()