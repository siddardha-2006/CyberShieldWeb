from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Cyber Shield"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    
    # Secrets & Cryptography
    JWT_SECRET: str = "cybershield-production-grade-jwt-secret-key-32bytes-min"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    
    CYBER_SHIELD_HMAC_SECRET: str = "cyber-shield-privacy-hmac-secret-key-2026"
    
    # Database
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DATABASE: str = "cyber_shield"
    
    # Threat Intelligence Keys (Optional - mock/heuristic fallback if empty)
    VIRUSTOTAL_API_KEY: str = ""
    URLHAUS_API_KEY: str = ""
    
    # Engine timeouts (in seconds)
    RULE_ENGINE_TIMEOUT: float = 3.0
    NLP_ENGINE_TIMEOUT: float = 5.0
    THREAT_INTEL_TIMEOUT: float = 4.0
    BEHAVIOR_TIMEOUT: float = 8.0
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

