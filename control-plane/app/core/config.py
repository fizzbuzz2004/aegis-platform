import os
from typing import Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis Control Plane API"
    VERSION: str = "1.0.0"
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://aegis_admin:aegis_secure_password_2026@localhost:5432/aegis_db"
    )

    # Security & Initial Provisioning
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-aegis-key-change-me-2026-prod")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))
    ADMIN_INITIAL_PASSWORD: Optional[str] = os.getenv("ADMIN_INITIAL_PASSWORD")

    class Config:
        case_sensitive = True

settings = Settings()
