"""
Threat intelligence integrations. Every integration is optional and keyed
off an environment variable. If a key is not configured, the module
returns a clearly-labeled "unavailable" result instead of erroring or
faking data. No API key is ever exposed to the frontend — all calls
happen server-side.
"""
import requests

from ..config import get_settings
from .utils import safe_ok, safe_fail

UNCONFIGURED = "Source unavailable — API key not configured."


def _unconfigured(source: str) -> dict:
    return safe_fail(source, UNCONFIGURED)


def check_virustotal(indicator: str, indicator_type: str, timeout: float = 8.0) -> dict:
    settings = get_settings()
    if not settings.VIRUSTOTAL_API_KEY:
        return _unconfigured("VirusTotal")

    endpoint_map = {"domain": "domains", "ip": "ip_addresses", "url": "urls"}
    endpoint = endpoint_map.get(indicator_type)
    if not endpoint:
        return safe_fail("VirusTotal", "Unsupported indicator type")

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return safe_fail("VirusTotal", "Request timed out")
    except requests.exceptions.RequestException as exc:
        return safe_fail("VirusTotal", f"Request failed: {exc}")

    if resp.status_code == 404:
        return safe_ok("VirusTotal", {"found": False, "note": "No data found for this indicator"})
    if resp.status_code == 401:
        return safe_fail("VirusTotal", "Invalid API key")
    if resp.status_code == 429:
        return safe_fail("VirusTotal", "Rate limit exceeded")
    if not resp.ok:
        return safe_fail("VirusTotal", f"Request failed with status {resp.status_code}")

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return safe_ok("VirusTotal", {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
    })


def check_abuseipdb(ip: str, timeout: float = 8.0) -> dict:
    settings = get_settings()
    if not settings.ABUSEIPDB_API_KEY:
        return _unconfigured("AbuseIPDB")

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return safe_fail("AbuseIPDB", "Request timed out")
    except requests.exceptions.RequestException as exc:
        return safe_fail("AbuseIPDB", f"Request failed: {exc}")

    if resp.status_code == 401:
        return safe_fail("AbuseIPDB", "Invalid API key")
    if resp.status_code == 429:
        return safe_fail("AbuseIPDB", "Rate limit exceeded")
    if not resp.ok:
        return safe_fail("AbuseIPDB", f"Request failed with status {resp.status_code}")

    data = resp.json().get("data", {})
    return safe_ok("AbuseIPDB", {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "is_whitelisted": data.get("isWhitelisted"),
        "last_reported_at": data.get("lastReportedAt"),
    })


def check_alienvault_otx(indicator: str, indicator_type: str, timeout: float = 8.0) -> dict:
    settings = get_settings()
    if not settings.ALIENVAULT_API_KEY:
        return _unconfigured("AlienVault OTX")

    section_map = {"domain": "domain", "ip": "IPv4", "url": "url"}
    section = section_map.get(indicator_type)
    if not section:
        return safe_fail("AlienVault OTX", "Unsupported indicator type")

    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general",
            headers={"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY},
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return safe_fail("AlienVault OTX", "Request timed out")
    except requests.exceptions.RequestException as exc:
        return safe_fail("AlienVault OTX", f"Request failed: {exc}")

    if resp.status_code == 403:
        return safe_fail("AlienVault OTX", "Invalid API key")
    if not resp.ok:
        return safe_fail("AlienVault OTX", f"Request failed with status {resp.status_code}")

    payload = resp.json()
    pulse_info = payload.get("pulse_info", {})
    return safe_ok("AlienVault OTX", {
        "pulse_count": pulse_info.get("count", 0),
        "related_pulses": [p.get("name") for p in pulse_info.get("pulses", [])[:5]],
    })


def check_shodan(ip: str, timeout: float = 8.0) -> dict:
    settings = get_settings()
    if not settings.SHODAN_API_KEY:
        return _unconfigured("Shodan")

    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": settings.SHODAN_API_KEY},
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return safe_fail("Shodan", "Request timed out")
    except requests.exceptions.RequestException as exc:
        return safe_fail("Shodan", f"Request failed: {exc}")

    if resp.status_code == 404:
        return safe_ok("Shodan", {"found": False, "note": "No data found for this host"})
    if resp.status_code == 401:
        return safe_fail("Shodan", "Invalid API key")
    if not resp.ok:
        return safe_fail("Shodan", f"Request failed with status {resp.status_code}")

    data = resp.json()
    return safe_ok("Shodan", {
        "found": True,
        "open_ports": data.get("ports", []),
        "organization": data.get("org"),
        "operating_system": data.get("os"),
        "hostnames": data.get("hostnames", []),
    })


def gather_threat_intel(indicator: str, indicator_type: str) -> dict:
    """Run all configured threat-intel checks applicable to the indicator type."""
    results = {}

    if indicator_type in ("domain", "ip", "url"):
        results["virustotal"] = check_virustotal(indicator, indicator_type)
    if indicator_type == "ip":
        results["abuseipdb"] = check_abuseipdb(indicator)
        results["shodan"] = check_shodan(indicator)
    if indicator_type in ("domain", "ip", "url"):
        results["alienvault_otx"] = check_alienvault_otx(indicator, indicator_type)

    return results
