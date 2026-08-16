"""
Shared OSINT utilities: target-type detection, validation, sanitization,
SSRF guards, and safe-fail helpers.

Security notes:
- All user input is validated against strict allow-list patterns before use.
- Nothing here ever shells out to the OS based on user input.
- resolve-then-check pattern is used to block SSRF against private/loopback
  ranges before any outbound HTTP request is made on the user's behalf.
"""
import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    UNKNOWN = "unknown"


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)
EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,63}$"
)


class ValidationError(Exception):
    pass


def sanitize_input(raw: str) -> str:
    """Strip whitespace/control chars. Reject empty or oversized input."""
    if raw is None:
        raise ValidationError("Empty target")
    value = raw.strip()
    # remove control characters
    value = "".join(ch for ch in value if ch.isprintable())
    if not value:
        raise ValidationError("Empty target")
    if len(value) > 2048:
        raise ValidationError("Target too long")
    return value


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value))


def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value))


def is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def strip_www(domain: str) -> str:
    """Normalizes a WWW to a subdomain which does not had one in the input."""

    domain = domain.lower()
    if domain.startswith("www.") and domain.count(".") >= 2:
        return domain[4:]
    return domain

def detect_target_type(raw: str) -> tuple[TargetType, str]:
    """Detect the OSINT target type from sanitized user input."""
    value = sanitize_input(raw)

    if value.startswith(("http://", "https://")):
        if is_valid_url(value):
            return TargetType.URL, value
        raise ValidationError("Invalid URL")

    if "@" in value:
        if is_valid_email(value):
            return TargetType.EMAIL, value.lower()
        raise ValidationError("Invalid email address")

    if is_valid_ip(value):
        return TargetType.IP, value

    if is_valid_domain(value):
        return TargetType.DOMAIN, strip_www(value)

    raise ValidationError(
        "Could not determine target type. Enter a domain, IP address, URL, or email."
    )


# --- SSRF protection -------------------------------------------------------

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),   # carrier-grade NAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_blocked_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # fail closed
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return True
    return any(addr in net for net in _BLOCKED_NETWORKS)


@dataclass
class SafeResolution:
    hostname: str
    ip_addresses: list[str]
    blocked: bool
    reason: str | None = None


def safe_resolve_host(hostname: str, timeout: float = 4.0) -> SafeResolution:
    """
    Resolve a hostname and verify none of the resolved addresses point at
    private/internal infrastructure, to prevent SSRF via DNS rebinding
    before any HTTP request is made against user-supplied URLs/domains.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return SafeResolution(hostname, [], blocked=False, reason="DNS resolution failed")
    finally:
        socket.setdefaulttimeout(old_timeout)

    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return SafeResolution(hostname, [], blocked=False, reason="No addresses found")

    for addr in addresses:
        if is_blocked_ip(addr):
            return SafeResolution(
                hostname, addresses, blocked=True,
                reason="Target resolves to a private/internal address and was blocked"
            )
    return SafeResolution(hostname, addresses, blocked=False)


def safe_fail(source: str, message: str) -> dict:
    """Standard shape for a failed/unavailable OSINT source."""
    return {"source": source, "available": False, "error": message, "data": None}


def safe_ok(source: str, data) -> dict:
    return {"source": source, "available": True, "error": None, "data": data}
