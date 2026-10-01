def test_admin_login_success(client):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "securepassword123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_admin_login_invalid_password(client):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "wrongpassword"}
    )
    assert response.status_code == 401

def test_create_tenant_authorized(client):
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "securepassword123"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    create_res = client.post(
        "/api/v1/admin/tenants",
        json={"name": "Test Mandant GmbH", "psa_company_id": "comp_123"},
        headers=headers
    )
    assert create_res.status_code == 200
    tenant_data = create_res.json()
    assert tenant_data["name"] == "Test Mandant GmbH"
    assert "enrollment_code" in tenant_data

def test_agent_update_metadata_requires_host_token(client):
    response = client.get("/api/v1/agents/update")
    assert response.status_code == 401

def test_agent_update_metadata_returns_configured_release(client, db, monkeypatch):
    from app.core.config import settings
    from app.models.orm import HostDevice, Tenant

    tenant = Tenant(name="Update Test", enrollment_code="update-test-enrollment")
    db.add(tenant)
    db.flush()
    db.add(HostDevice(
        tenant_id=tenant.id,
        hostname="update-test-host",
        os_info="linux-amd64",
        host_token="ath_update-test-token",
    ))
    db.commit()
    monkeypatch.setattr(settings, "AGENT_UPDATE_VERSION", "1.2.3")
    monkeypatch.setattr(settings, "AGENT_UPDATE_URL", "https://updates.example/aegis-agent-linux")
    monkeypatch.setattr(settings, "AGENT_UPDATE_SHA256", "A" * 64)
    monkeypatch.setattr(settings, "AGENT_UPDATE_OS_INFO", "linux-amd64")

    response = client.get(
        "/api/v1/agents/update",
        headers={"Authorization": "Bearer ath_update-test-token"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "version": "1.2.3",
        "download_url": "https://updates.example/aegis-agent-linux",
        "sha256": "a" * 64,
        "os_info": "linux-amd64",
    }

def test_agent_update_metadata_rejects_insecure_release_url(client, db, monkeypatch):
    from app.core.config import settings
    from app.models.orm import HostDevice, Tenant

    tenant = Tenant(name="Update Test", enrollment_code="update-test-insecure")
    db.add(tenant)
    db.flush()
    db.add(HostDevice(
        tenant_id=tenant.id,
        hostname="update-test-host",
        os_info="linux-amd64",
        host_token="ath_update-insecure-token",
    ))
    db.commit()
    monkeypatch.setattr(settings, "AGENT_UPDATE_VERSION", "1.2.3")
    monkeypatch.setattr(settings, "AGENT_UPDATE_URL", "http://updates.example/aegis-agent-linux")
    monkeypatch.setattr(settings, "AGENT_UPDATE_SHA256", "a" * 64)
    monkeypatch.setattr(settings, "AGENT_UPDATE_OS_INFO", "linux-amd64")

    response = client.get(
        "/api/v1/agents/update",
        headers={"Authorization": "Bearer ath_update-insecure-token"},
    )

    assert response.status_code == 503

def test_agent_update_metadata_is_scoped_to_host_platform(client, db, monkeypatch):
    from app.core.config import settings
    from app.models.orm import HostDevice, Tenant

    tenant = Tenant(name="Update Test", enrollment_code="update-test-platform")
    db.add(tenant)
    db.flush()
    db.add(HostDevice(
        tenant_id=tenant.id,
        hostname="update-test-host",
        os_info="linux-arm64",
        host_token="ath_update-platform-token",
    ))
    db.commit()
    monkeypatch.setattr(settings, "AGENT_UPDATE_VERSION", "1.2.3")
    monkeypatch.setattr(settings, "AGENT_UPDATE_URL", "https://updates.example/aegis-agent-linux")
    monkeypatch.setattr(settings, "AGENT_UPDATE_SHA256", "a" * 64)
    monkeypatch.setattr(settings, "AGENT_UPDATE_OS_INFO", "linux-amd64")

    response = client.get(
        "/api/v1/agents/update",
        headers={"Authorization": "Bearer ath_update-platform-token"},
    )

    assert response.status_code == 204
