from fastapi import APIRouter

from ..config import get_settings

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
def health_check():
    settings = get_settings()
    return {
        "status": "ok",
        "version": "0.1.0",
        "configured_sources": {
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "alienvault_otx": bool(settings.ALIENVAULT_API_KEY),
            "shodan": bool(settings.SHODAN_API_KEY),
            "ip_geolocation": True,  # ip-api.com, no key required
        },
    }
