"""
WHOIS lookups for a domain. WHOIS data is frequently privacy-protected,
rate-limited, or entirely absent (e.g. some ccTLDs) - all such cases
degrade gracefully to "Not available" rather than raising an error.
"""
from datetime import datetime

import whois as whois_lib

from .utils import safe_ok, safe_fail


def _first(value):
    """WHOIS fields are sometimes a list, sometimes a scalar."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _fmt_date(value) -> str | None:
    value = _first(value)
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def lookup_whois(domain: str) -> dict:
    try:
        w = whois_lib.whois(domain)
    except Exception as exc:  # noqa: BLE001
        return safe_fail("WHOIS", f"WHOIS lookup failed: {exc}")

    if not w or not (w.domain_name or w.registrar):
        return safe_fail("WHOIS", "Not available")

    name_servers = w.name_servers
    if isinstance(name_servers, list):
        name_servers = sorted({ns.lower() for ns in name_servers if ns})
    elif name_servers:
        name_servers = [str(name_servers).lower()]
    else:
        name_servers = []

    status = w.status
    if isinstance(status, list):
        status = status
    elif status:
        status = [str(status)]
    else:
        status = []

    data = {
        "domain": _first(w.domain_name) or domain,
        "registrar": _first(w.registrar) or "Not available",
        "creation_date": _fmt_date(w.creation_date) or "Not available",
        "updated_date": _fmt_date(w.updated_date) or "Not available",
        "expiration_date": _fmt_date(w.expiration_date) or "Not available",
        "status": status or ["Not available"],
        "name_servers": name_servers or ["Not available"],
        "registrant_org": _first(getattr(w, "org", None)) or "Not available (privacy protected)",
        "country": _first(getattr(w, "country", None)) or "Not available",
    }
    return safe_ok("WHOIS", data)
