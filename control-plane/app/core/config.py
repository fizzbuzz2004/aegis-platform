import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis Control Plane API"
    VERSION: str = "1.0.0"
    
    # Werte werden automatisch aus /run/secrets/<variablen_name> geladen, 
    # falls keine normale Umgebungsvariable existiert.
    DATABASE_URL: str
    SECRET_KEY: str
    ADMIN_INITIAL_PASSWORD: str
    
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

    # Pydantic liest die Dateien im angegebenen Ordner aus
    model_config = SettingsConfigDict(
        secrets_dir="/run/secrets", 
        case_sensitive=True
    )

settings = Settings()
