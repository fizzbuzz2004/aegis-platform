from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
from app.core.config import settings

is_sqlite = settings.DATABASE_URL.startswith("sqlite")

if is_sqlite:
    if ":memory:" in settings.DATABASE_URL or settings.DATABASE_URL == "sqlite://":
        engine = create_engine(
            settings.DATABASE_URL,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        engine = create_engine(
            settings.DATABASE_URL,
            connect_args={"check_same_thread": False}
        )
else:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=5,
        max_overflow=10
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def set_v1_tenant_context(session, tenant_id: int | None = None) -> None:
    """Setzt den PostgreSQL-Mandantenkontext für RLS im V1-Datenbankpfad."""
    if not is_sqlite and session.in_transaction():
        tenant_val = str(tenant_id) if tenant_id is not None else ""
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": tenant_val}
        )

def get_db():
    db = SessionLocal()
    try:
        # Optionaler Hook zur Transaktionsinitialisierung für RLS
        yield db
    finally:
        db.close()
