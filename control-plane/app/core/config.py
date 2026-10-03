import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis Control Plane API"
    VERSION: str = "1.0.0"
    
    # Werte werden automatisch aus der .env-Datei oder /run/secrets/ geladen
    DATABASE_URL: str
    AEGIS_V2_DATABASE_URL: Optional[str] = None
    SECRET_KEY: str
    ADMIN_INITIAL_PASSWORD: str

    AGENT_UPDATE_VERSION: Optional[str] = None
    AGENT_UPDATE_URL: Optional[str] = None
    AGENT_UPDATE_SHA256: Optional[str] = None
    AGENT_UPDATE_OS_INFO: Optional[str] = None
    AGENT_UPDATE_SIGNATURE: Optional[str] = None

    AEGIS_MTLS_ENABLED: bool = True
    AEGIS_TLS_CERT_FILE: Optional[str] = None
    AEGIS_TLS_KEY_FILE: Optional[str] = None
    AEGIS_TLS_CA_FILE: Optional[str] = None

    AWS_REGION: str = "eu-central-1"
    EVIDENCE_KMS_KEY_ARN: Optional[str] = None
    EVIDENCE_BUCKET: Optional[str] = None
    EVIDENCE_RETENTION_DAYS: int = 2555
    
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
