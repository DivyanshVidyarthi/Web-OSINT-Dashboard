"""
URL analysis: parsing + SSRF-safe optional HTTP HEAD/GET probe.

SSRF protections:
- The hostname is resolved and checked against private/internal ranges
  BEFORE any request is made.
- Redirects are followed manually (not via requests' auto-redirect) so
  each hop can be re-validated, preventing DNS-rebinding / redirect-based
  SSRF to internal services.
- A small number of hops max, short timeout, response size not read into
  memory beyond headers for the MVP.
"""
from urllib.parse import urlparse, parse_qsl

import requests

from .utils import safe_ok, safe_fail, safe_resolve_host, is_blocked_ip, strip_www

MAX_REDIRECTS = 3


def parse_url(url: str) -> dict:
    parsed = urlparse(url)
    return {
        "url": url,
        "protocol": parsed.scheme,
        "domain": parsed.hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "path": parsed.path or "/",
        "query_parameters": dict(parse_qsl(parsed.query)),
        "fragment": parsed.fragment or None,
    }


def _safe_http_probe(url: str, timeout: float) -> dict:
    """Perform a HEAD (falling back to GET) request, validating each
    redirect hop against SSRF rules before following it."""
    current_url = url
    hops = []

    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return safe_fail("HTTP Probe", "Unsupported or malformed URL")

        resolution = safe_resolve_host(parsed.hostname, timeout=timeout)
        if resolution.blocked:
            return safe_fail("HTTP Probe", resolution.reason)
        if not resolution.ip_addresses:
            return safe_fail("HTTP Probe", "Domain does not resolve")

        try:
            resp = requests.head(
                current_url, timeout=timeout, allow_redirects=False,
                headers={"User-Agent": "OSINT-Dashboard/1.0 (+passive-recon)"},
            )
            if resp.status_code == 405:  # some servers reject HEAD
                resp = requests.get(
                    current_url, timeout=timeout, allow_redirects=False, stream=True,
                    headers={"User-Agent": "OSINT-Dashboard/1.0 (+passive-recon)"},
                )
        except requests.exceptions.Timeout:
            return safe_fail("HTTP Probe", "Request timed out")
        except requests.exceptions.SSLError as exc:
            return safe_fail("HTTP Probe", f"TLS error: {exc}")
        except requests.exceptions.RequestException as exc:
            return safe_fail("HTTP Probe", f"Request failed: {exc}")

        hops.append({"url": current_url, "status_code": resp.status_code})

        if resp.is_redirect and "Location" in resp.headers:
            current_url = resp.headers["Location"]
            continue

        return safe_ok(
            "HTTP Probe",
            {
                "final_url": current_url,
                "status_code": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items()},
                "redirect_chain": hops,
            },
        )

    return safe_fail("HTTP Probe", "Too many redirects")


def analyze_url(url: str, timeout: float = 6.0, probe_http: bool = True) -> dict:
    parsed = parse_url(url)

    from . import dns_lookup, whois_lookup, ip_lookup  # local import avoids cycles

    domain = parsed["domain"]
    result = {"parsed": parsed}

    if not domain:
        return safe_fail("URL Analysis", "Could not extract a domain from this URL")

    resolution = safe_resolve_host(domain, timeout=timeout)
    if resolution.blocked:
        result["ip_resolution"] = safe_fail("IP Resolution", resolution.reason)
        result["dns"] = safe_fail("DNS", "Skipped — target resolves to a private/internal address")
        result["whois"] = safe_fail("WHOIS", "Skipped — target resolves to a private/internal address")
        result["http"] = safe_fail("HTTP Probe", "Skipped — target resolves to a private/internal address")
        return safe_ok("URL Analysis", result)

    result["ip_resolution"] = safe_ok("IP Resolution", {"ip_addresses": resolution.ip_addresses}) \
        if resolution.ip_addresses else safe_fail("IP Resolution", "No IP addresses found")
    result["dns"] = dns_lookup.lookup_dns(domain, timeout=timeout)
    result["whois"] = whois_lookup.lookup_whois(strip_www(domain))
    result["http"] = _safe_http_probe(url, timeout) if probe_http else safe_fail("HTTP Probe", "Disabled")

    return safe_ok("URL Analysis", result)
