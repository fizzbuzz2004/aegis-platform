import os

# Dummy-Umgebungswerte für Tests setzen, bevor Pydantic die Settings lädt
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test_secret_key_fuer_unit_tests_123456789"
os.environ["ADMIN_INITIAL_PASSWORD"] = "TestPassword123!"

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.main
app = app.main.app
from app.core.database import Base, engine, SessionLocal, get_db
from app.core.security import get_password_hash

# ORM-Modelle registrieren
import app.models.orm
from app.models.orm import User, UserRole

# Schutz vor Package-Kollisionen: Verifiziere, dass app eine FastAPI-Instanz ist
assert isinstance(app, FastAPI), "Importiertes 'app' ist keine FastAPI-Instanz!"

@pytest.fixture(scope="function")
def db():
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
