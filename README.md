# OSINT Dashboard

A publicly-deployable OSINT aggregation dashboard for cybersecurity research
and reconnaissance. Given a **domain, IP address, URL, or email address**,
it collects intelligence from public sources (DNS, WHOIS, IP geolocation,
optional threat-intel APIs) and presents it in one dashboard, with source
attribution and a non-definitive findings summary.

This project only collects information from **publicly available sources or
legitimate APIs**. It does not implement credential attacks, account
takeover, exploitation, or any form of unauthorized access.

## 1. Technology stack

| Layer      | Choice                          | Why |
|------------|----------------------------------|-----|
| Backend    | Python 3.12 + FastAPI + Uvicorn  | Async, typed, fast to iterate, great for I/O-bound OSINT calls |
| Frontend   | Static HTML/CSS/vanilla JS       | No build step, ships as static files served by the same backend — simplest path to a real MVP |
| Database   | SQLite                           | Zero-ops persistence sufficient for investigation history at MVP scale |
| DNS        | `dnspython`                      | Mature, well-tested resolver library |
| WHOIS      | `python-whois`                   | Simple WHOIS client with graceful failure |
| HTTP       | `requests`                       | Used for geolocation + threat-intel APIs + SSRF-safe URL probing |
| Deployment | Docker / docker-compose          | Single-container deploy; env-var driven config |

## 2. Directory structure

```text
osint-dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, CORS, static mount
│   │   ├── config.py          # Env-var driven settings
│   │   ├── db.py              # SQLite persistence (history)
│   │   ├── models.py          # Pydantic request/response models
│   │   ├── aggregator.py      # Orchestrates OSINT modules per target type
│   │   ├── rate_limit.py      # In-memory per-IP rate limiter
│   │   ├── osint/
│   │   │   ├── utils.py           # validation, target detection, SSRF guards
│   │   │   ├── dns_lookup.py
│   │   │   ├── whois_lookup.py
│   │   │   ├── ip_lookup.py
│   │   │   ├── geolocation.py
│   │   │   ├── email_osint.py
│   │   │   ├── url_analysis.py
│   │   │   ├── threat_intel.py
│   │   │   └── findings.py
│   │   └── routers/
│   │       ├── investigate.py
│   │       ├── history.py
│   │       └── health.py
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
├── frontend/
│   ├── index.html
│   └── static/{css,js}/
├── docker-compose.yml
└── README.md
```

## 3. Database choice

SQLite, via the standard library `sqlite3` — a single file at
`DATABASE_PATH`. This is sufficient for an MVP's investigation history
(target, type, timestamp, status, and the stored result JSON). For a
multi-instance production deployment, swap `db.py` for a Postgres-backed
implementation behind the same function signatures.

## 4. API architecture

REST over JSON, one FastAPI app, three routers:

```text
POST   /api/investigate            → run a new investigation
GET    /api/investigations         → list investigation history
GET    /api/investigations/{id}    → fetch one stored investigation
DELETE /api/investigations/{id}    → delete one investigation
DELETE /api/investigations         → clear all history
GET    /api/health                 → service + configured-source status
```

The backend never returns partial-crash errors: every OSINT module call is
wrapped so one failing source degrades to `"available": false` with a
message, while the rest of the investigation completes.

## 5. OSINT modules

Each module in `backend/app/osint/` has one responsibility and always
returns the same envelope shape:

```json
{ "source": "WHOIS", "available": true, "error": null, "data": { ... } }
```

- `dns_lookup.py` — A/AAAA/MX/NS/TXT/CNAME/SOA + reverse DNS (PTR)
- `whois_lookup.py` — registrar, dates, status, name servers
- `ip_lookup.py` — classification (v4/v6, private/public), orchestrates reverse DNS + geolocation
- `geolocation.py` — country/region/city/lat-lon/ISP/ASN via ip-api.com (approximate, clearly labeled)
- `email_osint.py` — format validation, domain/MX checks, disposable-domain heuristic (no account access)
- `url_analysis.py` — parsing + SSRF-safe HTTP HEAD probe with per-hop redirect validation
- `threat_intel.py` — VirusTotal / AbuseIPDB / AlienVault OTX / Shodan, each optional
- `findings.py` — derives INFO/LOW/MEDIUM/HIGH findings with source attribution

## 6. External APIs

| Source              | Key required | Free tier | Notes |
|---------------------|--------------|-----------|-------|
| ip-api.com          | No           | Yes (rate-limited) | Geolocation + ASN, used by default |
| VirusTotal          | Yes          | Yes | Domain/IP/URL reputation |
| AbuseIPDB           | Yes          | Yes | IP abuse confidence score |
| AlienVault OTX       | Yes          | Yes | Pulse/indicator context |
| Shodan              | Yes          | Paid | Host/port/service info |

If a key is missing, the dashboard shows **"Source unavailable — API key
not configured."** instead of erroring or faking data.

## 7. Environment variables

See `backend/.env.example`. Copy it to `backend/.env` and fill in any
threat-intel keys you have — all are optional.

## 8. Security controls

- Strict allow-list input validation + sanitization for all target types
- SSRF protection: hostnames are resolved and checked against
  private/loopback/link-local/metadata ranges **before** any outbound
  request; URL redirects are followed manually and re-validated per hop
- No shell execution of any kind based on user input (no command injection surface)
- No path traversal surface (no user-controlled filesystem paths)
- API keys read only from environment variables, never sent to the frontend
- Per-IP in-memory rate limiting (`RATE_LIMIT_PER_MINUTE`, default 10/min)
- Request timeouts on every outbound call
- CORS restricted to configured origins
- All exceptions caught and logged; a single failing OSINT source can never
  crash the request or take down other sources

## 9. Development phases

1. **Core MVP** — target input/detection, DNS, WHOIS, IP, geolocation, ASN, dashboard *(this build)*
2. **OSINT sources** — VirusTotal, AbuseIPDB, AlienVault OTX, Shodan *(scaffolded, enable via env vars)*
3. **Investigation management** — history, reports, export *(included)*
4. **Security & deployment hardening** — Docker, production config, expanded rate limiting/logging

---

## Running locally

```bash
cd backend
cp .env.example .env         # fill in any threat-intel keys you have
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000 — the backend also serves the static frontend.

## Running with Docker

```bash
cp backend/.env.example backend/.env
docker compose up --build
```

## Disclaimer

This tool aggregates information from publicly available sources only.
Results may be incomplete or inaccurate and should be independently
verified. It must not be used to attempt unauthorized access to any
system or account.
