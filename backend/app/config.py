"""
Central configuration. All secrets/config come from environment variables.
Never hard-code API keys here.
"""
import os
from functools import lru_cache


class Settings:
    # --- App ---
    APP_NAME: str = "OSINT Dashboard"
    ENV: str = os.getenv("ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

    # --- CORS ---
    CORS_ORIGINS: list[str] = [
        o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8000").split(",")
        if o.strip()
    ]

    # --- Database ---
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "./data/osint_dashboard.db")

    # --- Rate limiting ---
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))

    # --- Timeouts ---
    REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "8"))

    # --- Threat intel / third-party API keys (optional) ---
    VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY") or None
    ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY") or None
    ALIENVAULT_API_KEY: str | None = os.getenv("ALIENVAULT_API_KEY") or None
    SHODAN_API_KEY: str | None = os.getenv("SHODAN_API_KEY") or None

    # --- Geolocation provider (free, no key required by default: ip-api.com) ---
    IP_GEOLOCATION_PROVIDER: str = os.getenv("IP_GEOLOCATION_PROVIDER", "ip-api")


@lru_cache
def get_settings() -> Settings:
    return Settings()
