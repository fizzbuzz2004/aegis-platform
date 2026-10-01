from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app import main
from app.core.database import Base, get_db
from app.models.orm import User, UserRole


def _bootstrap_database(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(bind=engine))
    return engine, sessionmaker(bind=engine)


def test_seed_updates_stale_initial_admin_password(monkeypatch):
    engine, session_factory = _bootstrap_database(monkeypatch)
    monkeypatch.setattr(main.settings, "ADMIN_INITIAL_PASSWORD", "ConfiguredAdminPassword2026!")
    monkeypatch.setattr(main, "verify_password", lambda plain, hashed: hashed == f"hash:{plain}")
    monkeypatch.setattr(main, "get_password_hash", lambda password: f"hash:{password}")

    db = session_factory()
    db.add(User(
        username="admin",
        hashed_password="hash:old-password",
        role=UserRole.ADMIN,
        is_active=True,
        must_change_password=True,
    ))
    db.commit()
    db.close()

    try:
        main.seed_initial_data()
        db = session_factory()
        admin_user = db.query(User).filter_by(username="admin").one()
        assert admin_user.hashed_password == "hash:ConfiguredAdminPassword2026!"
        assert admin_user.must_change_password is True
        db.close()
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_seed_preserves_admin_password_after_password_change(monkeypatch):
    engine, session_factory = _bootstrap_database(monkeypatch)
    monkeypatch.setattr(main.settings, "ADMIN_INITIAL_PASSWORD", "ConfiguredAdminPassword2026!")
    monkeypatch.setattr(main, "verify_password", lambda plain, hashed: hashed == f"hash:{plain}")
    monkeypatch.setattr(main, "get_password_hash", lambda password: f"hash:{password}")

    db = session_factory()
    db.add(User(
        username="admin",
        hashed_password="hash:user-selected-password",
        role=UserRole.ADMIN,
        is_active=True,
        must_change_password=False,
    ))
    db.commit()
    db.close()

    try:
        main.seed_initial_data()
        db = session_factory()
        admin_user = db.query(User).filter_by(username="admin").one()
        assert admin_user.hashed_password == "hash:user-selected-password"
        assert admin_user.must_change_password is False
        db.close()
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_configured_bootstrap_password_authenticates_through_login_route(monkeypatch):
    engine, session_factory = _bootstrap_database(monkeypatch)
    password = "ChangeThisAdminPassword2026!"
    monkeypatch.setattr(main.settings, "ADMIN_INITIAL_PASSWORD", password)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    previous_override = main.app.dependency_overrides.get(get_db)
    main.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main.app) as client:
            response = client.post(
                "/api/v1/auth/login",
                data={"username": "admin", "password": password},
            )
        assert response.status_code == 200, response.text
        assert response.json()["token_type"] == "bearer"
        assert response.json()["access_token"]
    finally:
        if previous_override is None:
            main.app.dependency_overrides.pop(get_db, None)
        else:
            main.app.dependency_overrides[get_db] = previous_override
        Base.metadata.drop_all(bind=engine)
        engine.dispose()