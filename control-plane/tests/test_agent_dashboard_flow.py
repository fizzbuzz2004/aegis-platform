from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1 import admin as admin_api
from app.core.database import Base, get_db
from app.main import app
from app.models.orm import Tenant, TenantModule, User, UserRole


def test_agent_registration_results_reach_authenticated_dashboard(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    db = Session(engine)
    previous_db_override = app.dependency_overrides.get(get_db)

    tenant = Tenant(name="VirtualBox MSP", enrollment_code="vb-enroll-test")
    admin_user = User(
        username="admin",
        hashed_password="test-hash",
        role=UserRole.ADMIN,
        is_active=True,
        must_change_password=False,
    )
    db.add_all([tenant, admin_user])
    db.flush()
    db.add(TenantModule(tenant_id=tenant.id, module_name="firewall_status", is_enabled=True))
    db.commit()

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(admin_api, "verify_password", lambda password, hashed: password == "test-password" and hashed == "test-hash")

    try:
        client = TestClient(app)
        page = client.get("/api/v1/dashboard/ui")
        assert page.status_code == 200
        assert "/api/v1/auth/login" in page.text
        assert "aegis_admin_token" in page.text

        registration = client.post(
            "/api/v1/agents/register",
            json={
                "enrollment_code": "vb-enroll-test",
                "hostname": "ubuntu-agent-vm",
                "os_info": "linux-amd64",
            },
        )
        assert registration.status_code == 200, registration.text
        host_token = registration.json()["host_token"]
        host_headers = {"Authorization": f"Bearer {host_token}"}

        desired_state = client.get("/api/v1/agents/desired-state", headers=host_headers)
        assert desired_state.status_code == 200, desired_state.text
        assert desired_state.json() == {"firewall_status": True}

        pushed = client.post(
            "/api/v1/sync/results",
            headers=host_headers,
            json={
                "hostname": "ubuntu-agent-vm",
                "module_name": "firewall_status",
                "findings": [{
                    "status": "PASS",
                    "code": "FIREWALL_ACTIVE",
                    "severity": "INFO",
                    "message": "UFW meldet eine aktive Host-Firewall.",
                    "compliance": ["NIS2:Art21.2.e"],
                }],
            },
        )
        assert pushed.status_code == 200, pushed.text

        login = client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "test-password"},
        )
        assert login.status_code == 200, login.text
        admin_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        dashboard = client.get("/api/v1/dashboard/data", headers=admin_headers)
        assert dashboard.status_code == 200, dashboard.text
        tenant_data = dashboard.json()["tenants"][0]
        assert tenant_data["host_count"] == 1
        result = tenant_data["hosts"][0]["results"][0]
        assert result["module_name"] == "firewall_status"
        assert result["findings"][0]["code"] == "FIREWALL_ACTIVE"
    finally:
        if previous_db_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_db_override
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()