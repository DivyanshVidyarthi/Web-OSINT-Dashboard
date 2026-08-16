"""
Email OSINT — passive, publicly-available checks only.

Explicitly out of scope (never implemented here): password discovery,
account takeover, credential attacks, unauthorized login, or private
account enumeration of any kind.
"""
from .utils import safe_ok, safe_fail, is_valid_email
from . import dns_lookup

# Small, illustrative sample list. In production this should be backed by
# a maintained disposable-domain dataset (e.g. loaded from a config file
# and updated periodically) rather than a hard-coded list.
_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "yopmail.com", "trashmail.com", "getnada.com", "throwawaymail.com",
    "temp-mail.org", "fakeinbox.com", "sharklasers.com", "dispostable.com",
}


def analyze_email(email: str) -> dict:
    if not is_valid_email(email):
        return safe_fail("Email OSINT", "Invalid email format")

    domain = email.split("@", 1)[1].lower()

    dns_result = dns_lookup.lookup_dns(domain)
    mx_records = []
    domain_has_dns = dns_result["available"]
    if domain_has_dns:
        mx_records = dns_result["data"]["records"].get("MX", [])

    is_disposable = domain in _DISPOSABLE_DOMAINS

    data = {
        "email": email,
        "format_valid": True,
        "domain": domain,
        "domain_resolves": domain_has_dns,
        "mx_records": mx_records,
        "has_mail_server": len(mx_records) > 0,
        "is_disposable_domain": is_disposable,
        "breach_reputation": {
            "source": "Breach/reputation API",
            "available": False,
            "note": "Source unavailable — API key not configured.",
        },
        "scope_note": (
            "This check is limited to publicly available, passive information "
            "(format, domain DNS/MX, disposable-domain heuristics). No attempt "
            "is made to access, authenticate to, or enumerate the account."
        ),
    }
    return safe_ok("Email OSINT", data)
