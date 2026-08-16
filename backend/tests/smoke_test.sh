#!/usr/bin/env bash
# Smoke test for a running OSINT Dashboard instance.
# Run this AFTER starting the server (uvicorn or docker compose).
#
# Usage:
#   ./smoke_test.sh                       # tests http://localhost:8000
#   BASE_URL=http://localhost:8000 ./smoke_test.sh
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
PASS=0
FAIL=0

check() {
  local description="$1"
  local expected_status="$2"
  local method="$3"
  local path="$4"
  local body="${5:-}"

  local status
  if [ -n "$body" ]; then
    status=$(curl -s -o /tmp/smoke_resp.json -w "%{http_code}" -X "$method" \
      -H "Content-Type: application/json" -d "$body" "$BASE_URL$path")
  else
    status=$(curl -s -o /tmp/smoke_resp.json -w "%{http_code}" -X "$method" "$BASE_URL$path")
  fi

  if [ "$status" == "$expected_status" ]; then
    echo "  PASS  [$status] $description"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  [$status, expected $expected_status] $description"
    echo "        response: $(cat /tmp/smoke_resp.json | head -c 300)"
    FAIL=$((FAIL + 1))
  fi
}

echo "== OSINT Dashboard smoke test against $BASE_URL =="
echo

echo "-- Health --"
check "health endpoint responds"                200 GET  "/api/health"

echo
echo "-- Frontend --"
check "index page loads"                        200 GET  "/"
check "app.js is served"                         200 GET  "/static/js/app.js"
check "style.css is served"                      200 GET  "/static/css/style.css"

echo
echo "-- Investigate: valid targets --"
check "domain investigation succeeds"            200 POST "/api/investigate" '{"target":"example.com"}'
check "IP investigation succeeds"                200 POST "/api/investigate" '{"target":"8.8.8.8"}'
check "URL investigation succeeds"               200 POST "/api/investigate" '{"target":"https://example.com"}'
check "email investigation succeeds"             200 POST "/api/investigate" '{"target":"user@example.com"}'

echo
echo "-- Investigate: invalid / malicious targets --"
check "garbage input rejected with 400"          400 POST "/api/investigate" '{"target":"!!!not a target!!!"}'
check "empty target rejected with 400"           400 POST "/api/investigate" '{"target":""}'
check "SSRF attempt against loopback is handled" 200 POST "/api/investigate" '{"target":"http://127.0.0.1:8000/"}'
check "SSRF attempt against metadata IP handled" 200 POST "/api/investigate" '{"target":"169.254.169.254"}'

echo
echo "-- History --"
check "list investigations"                      200 GET  "/api/investigations"

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
