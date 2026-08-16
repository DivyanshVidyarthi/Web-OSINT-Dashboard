"""
Aggregates results from individual OSINT modules into the common response
structure returned by POST /api/investigate. Every external lookup is
wrapped so a single failing source can never crash the whole investigation.
"""
import logging
from datetime import datetime, timezone

from .osint.utils import TargetType, safe_fail
from .osint import dns_lookup, whois_lookup, ip_lookup, geolocation, email_osint, url_analysis, threat_intel
from .osint.findings import build_findings

logger = logging.getLogger("osint.aggregator")


def _try(label: str, fn, *args, **kwargs) -> dict:
    """Run an OSINT module call, converting any unexpected exception into
    a safe 'unavailable' result instead of propagating it."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.exception("OSINT module '%s' raised an unexpected error", label)
        return safe_fail(label, f"Unexpected error: {exc}")


def investigate(target: str, target_type: TargetType) -> dict:
    results: dict = {
        "target": target,
        "type": target_type.value,
        "status": "completed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if target_type == TargetType.DOMAIN:
        results["dns"] = _try("DNS", dns_lookup.lookup_dns, target)
        results["whois"] = _try("WHOIS", whois_lookup.lookup_whois, target)
        ip_res = _try("IP Resolution", ip_lookup.resolve_domain_to_ips, target)
        results["ip_resolution"] = ip_res
        primary_ip = None
        if ip_res.get("available"):
            ips = ip_res["data"]["ip_addresses"]
            primary_ip = ips[0] if ips else None
        results["ip"] = _try("IP Intelligence", ip_lookup.lookup_ip, primary_ip) if primary_ip else safe_fail("IP Intelligence", "No IP address resolved")
        results["geolocation"] = _try("IP Geolocation API", geolocation.lookup_geolocation, primary_ip) if primary_ip else safe_fail("IP Geolocation API", "No IP address resolved")
        results["threat_intelligence"] = _try("Threat Intelligence", threat_intel.gather_threat_intel, target, "domain")

    elif target_type == TargetType.IP:
        results["ip"] = _try("IP Intelligence", ip_lookup.lookup_ip, target)
        results["geolocation"] = _try("IP Geolocation API", geolocation.lookup_geolocation, target)
        results["threat_intelligence"] = _try("Threat Intelligence", threat_intel.gather_threat_intel, target, "ip")

    elif target_type == TargetType.EMAIL:
        results["email"] = _try("Email OSINT", email_osint.analyze_email, target)
        email_data = results["email"].get("data") if results["email"].get("available") else None
        domain = email_data["domain"] if email_data else None
        if domain:
            results["threat_intelligence"] = _try("Threat Intelligence", threat_intel.gather_threat_intel, domain, "domain")

    elif target_type == TargetType.URL:
        url_result = _try("URL Analysis", url_analysis.analyze_url, target)
        results["url"] = url_result
        if url_result.get("available"):
            domain = url_result["data"]["parsed"].get("domain")
            results["dns"] = url_result["data"].get("dns")
            results["whois"] = url_result["data"].get("whois")
            results["ip_resolution"] = url_result["data"].get("ip_resolution")
            if domain:
                results["threat_intelligence"] = _try("Threat Intelligence", threat_intel.gather_threat_intel, target, "url")

    results["findings"] = build_findings(target, target_type.value, results)
    return results
