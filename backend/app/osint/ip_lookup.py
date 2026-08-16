"""
Core IP intelligence: classification (v4/v6, private/public) plus
orchestration of reverse DNS + geolocation for a given IP.
"""
import ipaddress
import socket

from .utils import safe_ok, safe_fail, is_blocked_ip
from . import dns_lookup, geolocation


def classify_ip(ip: str) -> dict:
    addr = ipaddress.ip_address(ip)
    return {
        "ip": ip,
        "version": f"IPv{addr.version}",
        "is_private": addr.is_private,
        "is_loopback": addr.is_loopback,
        "is_multicast": addr.is_multicast,
        "is_reserved": addr.is_reserved,
    }


def resolve_domain_to_ips(domain: str, timeout: float = 5.0) -> dict:
    """Resolve a domain's A/AAAA records to concrete IP addresses."""
    ips: list[str] = []
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({info[4][0] for info in infos})
    except socket.gaierror as exc:
        return safe_fail("IP Resolution", f"Could not resolve domain: {exc}")
    finally:
        socket.setdefaulttimeout(old_timeout)

    if not ips:
        return safe_fail("IP Resolution", "No IP addresses found")
    return safe_ok("IP Resolution", {"ip_addresses": ips})


def lookup_ip(ip: str) -> dict:
    """Aggregate classification + reverse DNS + geolocation for an IP."""
    classification = classify_ip(ip)

    if classification["is_private"] or classification["is_loopback"] or is_blocked_ip(ip):
        return safe_ok(
            "IP Intelligence",
            {
                "classification": classification,
                "note": "This is a private/internal IP address. Public intelligence sources do not apply.",
                "reverse_dns": None,
                "geolocation": None,
            },
        )

    rdns = dns_lookup.reverse_dns(ip)
    geo = geolocation.lookup_geolocation(ip)

    return safe_ok(
        "IP Intelligence",
        {
            "classification": classification,
            "reverse_dns": rdns,
            "geolocation": geo,
        },
    )
