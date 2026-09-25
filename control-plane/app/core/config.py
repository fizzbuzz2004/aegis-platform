import os
from typing import Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis Control Plane API"
    VERSION: str = "1.0.0"
    
    # ISO27001 / BSI Vorgabe: Niemals Fallback-Secrets im Quellcode belassen.
    # Fail-Secure: Fehlt eine dieser Variablen, startet der Dienst absichtlich nicht.
    DATABASE_URL: str = os.environ["DATABASE_URL"]
    SECRET_KEY: str = os.environ["SECRET_KEY"]
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))
    ADMIN_INITIAL_PASSWORD: str = os.environ["ADMIN_INITIAL_PASSWORD"]

    class Config:
        case_sensitive = True

settings = Settings()
