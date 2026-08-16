"""
Derives a plain, non-definitive list of findings (INFO/LOW/MEDIUM/HIGH)
from aggregated OSINT results. This is a heuristic summary, not a
security verdict.
"""
from typing import Any


def _finding(level: str, text: str, source: str) -> dict:
    return {"level": level, "text": text, "source": source}


def build_findings(target: str, target_type: str, results: dict[str, Any]) -> list[dict]:
    findings: list[dict] = []

    dns_result = results.get("dns")
    if dns_result and dns_result.get("available"):
        records = dns_result["data"]["records"]
        total = sum(len(v) for v in records.values())
        if total > 0:
            findings.append(_finding("INFO", f"Domain has {total} DNS record(s) across {sum(1 for v in records.values() if v)} record type(s).", "DNS"))
        if records.get("MX"):
            findings.append(_finding("LOW", "Domain has mail (MX) records configured, indicating third-party or self-hosted email infrastructure.", "DNS"))
        if records.get("TXT"):
            spf = any("v=spf1" in t.lower() for t in records["TXT"])
            dmarc_like = any("v=dmarc1" in t.lower() for t in records["TXT"])
            if not spf:
                findings.append(_finding("LOW", "No SPF record detected in TXT records — this can make email spoofing easier.", "DNS"))
            if dmarc_like:
                findings.append(_finding("INFO", "A DMARC-like TXT record was found.", "DNS"))

    whois_result = results.get("whois")
    if whois_result and whois_result.get("available"):
        data = whois_result["data"]
        if data.get("status") and any("clienthold" in s.lower() or "serverhold" in s.lower() for s in data["status"]):
            findings.append(_finding("HIGH", "Domain status includes a hold status, which can indicate suspension or dispute.", "WHOIS"))
        if data.get("registrar") == "Not available":
            findings.append(_finding("INFO", "WHOIS registrar information is not available (may be privacy-protected).", "WHOIS"))
    elif whois_result and not whois_result.get("available"):
        findings.append(_finding("INFO", "WHOIS information is not available for this target.", "WHOIS"))

    geo = results.get("geolocation")
    if geo and geo.get("available"):
        gdata = geo["data"]
        if gdata.get("is_proxy_or_vpn"):
            findings.append(_finding("MEDIUM", "The resolved IP address appears to be associated with a known proxy or VPN service.", "IP Geolocation API"))
        if gdata.get("is_hosting_provider"):
            findings.append(_finding("INFO", "The resolved IP address belongs to a hosting/datacenter provider rather than a residential ISP.", "IP Geolocation API"))

    ti = results.get("threat_intelligence") or {}
    vt = ti.get("virustotal")
    if vt and vt.get("available") and vt["data"].get("found"):
        malicious = vt["data"].get("malicious", 0)
        if malicious > 0:
            findings.append(_finding("HIGH", f"VirusTotal reports {malicious} security vendor(s) flagging this indicator as malicious.", "VirusTotal"))
        else:
            findings.append(_finding("INFO", "VirusTotal reports no vendors currently flag this indicator as malicious.", "VirusTotal"))

    abuse = ti.get("abuseipdb")
    if abuse and abuse.get("available"):
        score = abuse["data"].get("abuse_confidence_score")
        if score is not None:
            if score >= 75:
                findings.append(_finding("HIGH", f"AbuseIPDB reports a high abuse confidence score ({score}/100) from external threat-intelligence reports.", "AbuseIPDB"))
            elif score >= 25:
                findings.append(_finding("MEDIUM", f"AbuseIPDB reports a moderate abuse confidence score ({score}/100).", "AbuseIPDB"))
            elif score > 0:
                findings.append(_finding("LOW", f"AbuseIPDB reports a low abuse confidence score ({score}/100).", "AbuseIPDB"))

    email_result = results.get("email")
    if email_result and email_result.get("available"):
        edata = email_result["data"]
        if edata.get("is_disposable_domain"):
            findings.append(_finding("MEDIUM", "The email domain appears to be disposable/temporary email infrastructure.", "Email OSINT"))
        if not edata.get("has_mail_server"):
            findings.append(_finding("MEDIUM", "The email's domain has no MX records — mail delivery to this address may fail.", "Email OSINT"))

    if not findings:
        findings.append(_finding("INFO", "No notable findings from the currently configured sources.", "System"))

    return findings
