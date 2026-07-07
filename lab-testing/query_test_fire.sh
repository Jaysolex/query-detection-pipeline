#!/usr/bin/env bash
#
# query_test_fire.sh
# ===================
# Sends a set of benign-but-signature-matching HTTP QUERY requests against
# a target you control, purely to validate that the Sigma/KQL/SPL rules in
# this repo actually fire end-to-end (gateway -> Wazuh -> Shuffle -> TheHive).
#
# THIS IS FOR YOUR OWN ISOLATED LAB ONLY (client01 / target you own).
# It does not exploit anything — it just sends the same literal strings
# the Sigma rules pattern-match on, wrapped in a syntactically valid QUERY
# request, against a test endpoint you stand up yourself (e.g. a throwaway
# nginx/Flask listener on client01). There is no live target, no scanning
# of other hosts, and no payload beyond the test strings already documented
# in sigma/query_002_body_injection_signatures.yml.
#
# Usage:
#   ./query_test_fire.sh http://client01.lab:8080/api/search
#
# Expected result if wired correctly:
#   - Wazuh should log 5 distinct QUERY events
#   - The 4 "malicious-pattern" requests should trigger query_002/query_003
#   - The 1 "benign" request should NOT trigger anything (false-positive check)

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url>"
    echo "Example: $0 http://client01.lab:8080/api/search"
    exit 1
fi

echo "== QUERY detection test-fire against: $TARGET =="
echo "(Confirm this target is inside your isolated lab before proceeding.)"
read -r -p "Continue? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
fi

curl_query() {
    local label="$1"
    local body="$2"
    echo "--- Sending: $label ---"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" \
        -X QUERY "$TARGET" \
        -H "Content-Type: application/json" \
        -d "$body"
    sleep 1
}

# 1. Missing Content-Type -> should fire query_001
echo "--- Sending: missing content-type ---"
curl -s -o /dev/null -w "  HTTP %{http_code}\n" \
    -X QUERY "$TARGET" \
    -H "Content-Type:" \
    -d '{"filter":"category=laptops"}'
sleep 1

# 2. SQLi signature -> should fire query_002
curl_query "SQLi pattern" '{"filter":{"value":"1 OR 1=1; DROP TABLE users;"}}'

# 3. NoSQLi signature -> should fire query_002
curl_query "NoSQLi pattern" '{"filter":{"$where":"this.password.length > 0"}}'

# 4. Base64-encoded traversal -> should fire query_002 (after decode by normalize.py)
ENCODED_TRAVERSAL=$(printf '../../etc/passwd' | base64)
curl_query "Encoded traversal" "{\"path\":\"${ENCODED_TRAVERSAL}\"}"

# 5. Deeply nested / oversized body -> should fire query_003 behavioral rule
DEEP_JSON='{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":"deep"}}}}}}}}}}}}}'
curl_query "Deep nesting (behavioral)" "$DEEP_JSON"

# 6. Clean/benign query -> should NOT fire anything (false-positive check)
curl_query "Benign control (should NOT alert)" '{"category":"laptops","sort":"price","page":1}'

echo ""
echo "== Done. Now check: =="
echo "  1. Wazuh dashboard  -> confirm 6 QUERY events logged"
echo "  2. Wazuh rules      -> confirm requests 2-5 triggered alerts, request 1 (missing CT) triggered query_001, request 6 did NOT alert"
echo "  3. Shuffle          -> confirm the webhook fired and enrichment ran for the alerting events"
echo "  4. TheHive          -> confirm a case was created for score >= your configured threshold"
