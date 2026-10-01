import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.dashboard import get_dashboard_data
from app.api.v1.reporting import generate_monthly_compliance_report
from app.api.v1 import admin as admin_api
from app.core.database import Base
from app.models.orm import HostDevice, ModuleResult, PSAAlertState, Tenant, User, UserRole, WebhookConfig
from app.services import backup_alerts


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_backup_psa_ticket_waits_48_hours_and_is_deduplicated(db, monkeypatch):
    now = datetime.now(timezone.utc)
    tenant = Tenant(name="MSP customer", enrollment_code="customer-code")
    db.add(tenant)
    db.flush()
    db.add(WebhookConfig(
        tenant_id=tenant.id,
        url="https://psa.example.test/tickets",
        secret_token="a-long-enough-webhook-secret",
    ))
    for age_hours in (49, 47):
        db.add(ModuleResult(
            tenant_id=tenant.id,
            hostname="backup-host",
            module_name="backup_probe",
            timestamp=now - timedelta(hours=age_hours),
            findings=json.dumps([{"status": "FAIL", "severity": "HIGH", "code": "BACKUP_FAILED"}]),
        ))
    db.commit()

    dispatches = []
    monkeypatch.setattr(
        backup_alerts.PSADispatcher,
        "dispatch_event",
        lambda **kwargs: dispatches.append(kwargs) or True,
    )

    assert backup_alerts.evaluate_backup_alerts(db, now - timedelta(hours=2)) == 0
    assert not dispatches
    assert backup_alerts.evaluate_backup_alerts(db, now) == 1
    assert len(dispatches) == 1
    assert dispatches[0]["payload"]["findings"][0]["code"] == "BACKUP_FAILED"
    assert backup_alerts.evaluate_backup_alerts(db, now + timedelta(minutes=15)) == 0
    assert len(dispatches) == 1
    assert db.query(PSAAlertState).one().ticket_created_at is not None


def test_backup_probe_staleness_triggers_ticket(db, monkeypatch):
    now = datetime.now(timezone.utc)
    tenant = Tenant(name="Stale customer", enrollment_code="stale-code")
    db.add(tenant)
    db.flush()
    db.add(WebhookConfig(tenant_id=tenant.id, url="https://psa.example.test", secret_token="a-long-enough-webhook-secret"))
    db.add(ModuleResult(
        tenant_id=tenant.id,
        hostname="offline-host",
        module_name="backup_probe",
        timestamp=now - timedelta(hours=48),
        findings=json.dumps([{"status": "PASS", "severity": "INFO", "code": "BACKUP_OK"}]),
    ))
    db.commit()

    dispatches = []
    monkeypatch.setattr(
        backup_alerts.PSADispatcher,
        "dispatch_event",
        lambda **kwargs: dispatches.append(kwargs) or True,
    )

    assert backup_alerts.evaluate_backup_alerts(db, now) == 1
    assert dispatches[0]["payload"]["findings"][-1]["code"] == "BACKUP_STALE"


def test_customer_admin_dashboard_and_report_are_tenant_scoped(db):
    own_tenant = Tenant(name="Own tenant", enrollment_code="own-code")
    other_tenant = Tenant(name="Other tenant", enrollment_code="other-code")
    db.add_all([own_tenant, other_tenant])
    db.flush()
    customer_admin = User(
        username="customer-admin",
        hashed_password="unused",
        role=UserRole.CUSTOMER_ADMIN,
        tenant_id=own_tenant.id,
    )
    db.add_all([
        customer_admin,
        HostDevice(tenant_id=own_tenant.id, hostname="own-host", os_info="linux", host_token="own-token"),
        HostDevice(tenant_id=other_tenant.id, hostname="other-host", os_info="linux", host_token="other-token"),
    ])
    db.commit()

    dashboard = get_dashboard_data(customer_admin, db)
    assert [tenant["id"] for tenant in dashboard["tenants"]] == [own_tenant.id]

    with pytest.raises(HTTPException) as error:
        generate_monthly_compliance_report(other_tenant.id, customer_admin, db)
    assert error.value.status_code == 403


def test_technician_dashboard_includes_all_tenants(db):
    tenants = [
        Tenant(name="Tenant one", enrollment_code="tenant-one"),
        Tenant(name="Tenant two", enrollment_code="tenant-two"),
    ]
    db.add_all(tenants)
    db.flush()
    technician = User(username="tech", hashed_password="unused", role=UserRole.TECHNICIAN)
    db.add(technician)
    db.commit()

    dashboard = get_dashboard_data(technician, db)
    assert {tenant["id"] for tenant in dashboard["tenants"]} == {tenant.id for tenant in tenants}


def test_customer_admin_can_configure_psa_only_for_own_tenant(db):
    own_tenant = Tenant(name="Own PSA tenant", enrollment_code="own-psa")
    other_tenant = Tenant(name="Other PSA tenant", enrollment_code="other-psa")
    db.add_all([own_tenant, other_tenant])
    db.flush()
    customer_admin = User(
        username="psa-customer-admin",
        hashed_password="unused",
        role=UserRole.CUSTOMER_ADMIN,
        tenant_id=own_tenant.id,
    )
    db.add(customer_admin)
    db.commit()
    payload = admin_api.PSAWebhookCreateSchema(
        url="https://psa.example.test/webhook",
        secret_token="a-long-enough-webhook-secret",
        provider="halopsa",
        auth_header="Authorization",
        auth_value="Bearer api-key",
    )

    webhook = admin_api.create_psa_webhook(own_tenant.id, payload, customer_admin, db)
    response = admin_api.PSAWebhookResponseSchema.model_validate(webhook)
    assert response.provider == "halopsa"
    assert "secret_token" not in response.model_dump()

    with pytest.raises(HTTPException) as error:
        admin_api.create_psa_webhook(other_tenant.id, payload, customer_admin, db)
    assert error.value.status_code == 403


def test_global_technician_can_provision_tenant_admin(db, monkeypatch):
    tenant = Tenant(name="Assigned tenant", enrollment_code="assigned-code")
    db.add(tenant)
    db.commit()
    technician = User(username="provisioner", hashed_password="unused", role=UserRole.TECHNICIAN)
    monkeypatch.setattr(admin_api, "get_password_hash", lambda password: f"hashed:{password}")

    created = admin_api.create_user(
        admin_api.UserCreateSchema(
            username="new-customer-admin",
            password="a-secure-password",
            role=UserRole.CUSTOMER_ADMIN,
            tenant_id=tenant.id,
        ),
        technician,
        db,
    )

    assert created.role == UserRole.CUSTOMER_ADMIN
    assert created.tenant_id == tenant.id
    assert created.must_change_password is True