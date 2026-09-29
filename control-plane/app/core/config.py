import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis Control Plane API"
    VERSION: str = "1.0.0"
    
    # Werte werden automatisch aus der .env-Datei oder /run/secrets/ geladen
    DATABASE_URL: str
    SECRET_KEY: str
    ADMIN_INITIAL_PASSWORD: str
    
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

    # WICHTIG: env_file hinzugefügt, damit Pydantic Ihre .env-Datei ausliest
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir="/run/secrets", 
        case_sensitive=True,
        extra="ignore"
    )

settings = Settings()
