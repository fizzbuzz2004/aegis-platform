import os

# Dummy-Umgebungswerte für Tests setzen, bevor Pydantic die Settings lädt
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test_secret_key_fuer_unit_tests_123456789"
os.environ["ADMIN_INITIAL_PASSWORD"] = "TestPassword123!"

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine, SessionLocal, get_db
from app.core.security import get_password_hash
from app.models.orm import User, UserRole

@pytest.fixture(scope="function")
def db():
    # Erstellt die Tabellen auf dem exakt selben Engine-Objekt, das auch die App nutzt
    Base.metadata.create_all(bind=engine)
    db_session = SessionLocal()
    
    admin_user = User(
        username="admin",
        hashed_password=get_password_hash("securepassword123"),
        role=UserRole.ADMIN,
        is_active=True,
        must_change_password=False
    )
    db_session.add(admin_user)
    db_session.commit()
    
    try:
        yield db_session
    finally:
        db_session.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
