"""
IP geolocation + ASN/ISP lookup via ip-api.com (free tier, no API key
required, ~45 req/min). Geolocation from IP is always approximate and
this is surfaced explicitly to the user - never presented as exact.
"""
import requests

from .utils import safe_ok, safe_fail, is_blocked_ip

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,asname,query,mobile,proxy,hosting"


def lookup_geolocation(ip: str, timeout: float = 6.0) -> dict:
    if is_blocked_ip(ip):
        return safe_fail("IP Geolocation API", "Private/internal IP addresses cannot be geolocated")

    try:
        resp = requests.get(
            IP_API_URL.format(ip=ip),
            params={"fields": IP_API_FIELDS},
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
    except requests.exceptions.Timeout:
        return safe_fail("IP Geolocation API", "Request timed out")
    except requests.exceptions.RequestException as exc:
        return safe_fail("IP Geolocation API", f"Request failed: {exc}")
    except ValueError:
        return safe_fail("IP Geolocation API", "Invalid response from geolocation provider")

    if payload.get("status") != "success":
        return safe_fail("IP Geolocation API", payload.get("message", "No data found"))

    data = {
        "ip": payload.get("query", ip),
        "country": payload.get("country") or "Unknown",
        "country_code": payload.get("countryCode") or "Unknown",
        "region": payload.get("regionName") or "Unknown",
        "city": payload.get("city") or "Unknown",
        "latitude": payload.get("lat"),
        "longitude": payload.get("lon"),
        "isp": payload.get("isp") or "Unknown",
        "organization": payload.get("org") or "Unknown",
        "asn": payload.get("as") or "Unknown",
        "asn_name": payload.get("asname") or "Unknown",
        "is_mobile_network": payload.get("mobile", False),
        "is_proxy_or_vpn": payload.get("proxy", False),
        "is_hosting_provider": payload.get("hosting", False),
        "accuracy_notice": "Geolocation is approximate (typically city/region level) and derived from IP allocation data, not a precise physical location.",
    }
    return safe_ok("IP Geolocation API", data)
