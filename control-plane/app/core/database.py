from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Korrigierter Import (ohne das ungültige 'control-plane')
from app.core.config import settings
# Alternativ als relativer Import, da config.py im selben Ordner (core) liegt:
# from .config import settings

# Connection Pooling config for Enterprise high-concurrency loads
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=1800
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
