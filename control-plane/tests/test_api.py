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
