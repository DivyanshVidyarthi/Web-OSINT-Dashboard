"""
DNS record lookups for a domain. Uses dnspython. All failures are caught
and reported as "no data found" / "unavailable" rather than raising.
"""
import dns.resolver
import dns.reversename

from .utils import safe_ok, safe_fail

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def lookup_dns(domain: str, timeout: float = 5.0) -> dict:
    """Return all supported DNS record types for a domain."""
    resolver = _resolver(timeout)
    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}

    for rtype in RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, rtype)
            values = []
            for rdata in answer:
                if rtype == "MX":
                    values.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == "SOA":
                    values.append(
                        f"mname={rdata.mname} rname={rdata.rname} serial={rdata.serial}"
                    )
                elif rtype == "TXT":
                    values.append(
                        b"".join(rdata.strings).decode("utf-8", errors="replace")
                    )
                else:
                    values.append(str(rdata))
            records[rtype] = values
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            errors["domain"] = "Domain does not exist (NXDOMAIN)"
            break
        except dns.exception.Timeout:
            errors[rtype] = "DNS query timed out"
        except Exception as exc:  # noqa: BLE001
            errors[rtype] = str(exc)

    if errors.get("domain"):
        return safe_fail("DNS", errors["domain"])

    return safe_ok("DNS", {"records": records, "errors": errors})


def reverse_dns(ip: str, timeout: float = 5.0) -> dict:
    """PTR lookup for an IP address."""
    resolver = _resolver(timeout)
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = resolver.resolve(rev_name, "PTR")
        ptr_records = [str(r) for r in answer]
        return safe_ok("Reverse DNS", {"ptr": ptr_records})
    except dns.resolver.NXDOMAIN:
        return safe_ok("Reverse DNS", {"ptr": [], "note": "No PTR record found"})
    except dns.exception.Timeout:
        return safe_fail("Reverse DNS", "Query timed out")
    except Exception as exc:  # noqa: BLE001
        return safe_fail("Reverse DNS", str(exc))
