# HTTP QUERY Method Detection Pipeline (RFC 10008)

Detection-as-code for the newest HTTP method. RFC 10008 (IETF, June 2026)
standardized `QUERY` — safe/idempotent like GET, carries a body like POST —
but existing WAF, cache, and SIEM rulesets were mostly written before it
existed. This repo closes that gap: it inspects QUERY request bodies the
same way mature tooling already inspects POST, and adds a behavioral layer
This extends the signature-tuning methodology from

[Detection-Content](https://github.com/Jaysolex/Detection-Content) to a
protocol with effectively zero public detection content as of writing, and
is designed to feed the same scoring/routing pattern used in
[soar-ir-pipeline](https://github.com/Jaysolex/soar-ir-pipeline).

**See also:** [Architecture](docs/ARCHITECTURE.md) | [Threat Model](docs/THREAT_MODEL.md)


## What's actually here

- **`sigma/`** — 3 Sigma rules: missing/invalid Content-Type (protocol
  compliance), body injection signatures (SQLi/NoSQLi/cmdi/traversal), and
  a behavioral rule for anomalous body size/depth.
- **`kql/`, `splunk/`** — direct ports of the same 3 rules for Microsoft
  Sentinel and Splunk, matching the multi-platform pattern in
  [Detection-Content](https://github.com/Jaysolex/Detection-Content).
- **`wazuh/query_rules.xml`** — hand-authored Wazuh rules (100200-100204),
  since sigma-cli has no Wazuh backend (Wazuh evaluates XML/regex rules,
  not a query language, so there's nothing to "convert" — confirmed via
  `sigma plugin list` while building this). Validated live against the
  lab SIEM (see Testing section below).
- **`src/normalize.py`** — recursive decoder (URL → base64 → hex, capped at
  5 layers to prevent decode-bomb DoS on the pipeline itself), JSON
  flattener, signature scanner (scans both flattened keys and values —
  NoSQL operators like `$where`/`$regex` are JSON *keys*, not values, and
  an earlier version of this scanner missed them as a result; fixed after
  live testing surfaced it), and a per-endpoint rolling z-score baseline.
- **`shuffle/pb11_query_method_playbook.json`** — SOAR playbook matching
  the schema of [soar-ir-pipeline](https://github.com/Jaysolex/soar-ir-pipeline)'s
  existing PB-01 through PB-10, routing on the same `risk_score` computed
  by `normalize.py` into AbuseIPDB enrichment, TheHive case creation, and
  Slack notification.
- **`docs/PB-11_README.md`** — playbook documentation matching the existing
  `docs/PB-XX_README.md` convention.
- **`tests/test_normalize.py`** — 24 unit tests, including explicit
  false-positive guardrail tests (a clean analytics query with `SELECT`
  should *not* fire the SQLi rule).
- **`lab-testing/`** — a minimal Flask listener and a test-fire script used
  to validate the full pipeline against real HTTP traffic (see Testing).
- **`.github/workflows/ci.yml`** — runs the test suite and validates Sigma
  syntax on every push, same detection-as-code pattern as production Sigma
  repos (rule changes are tested before they can be merged).

## Testing — validated end-to-end, not just unit tests

This was tested at three increasing levels of rigor, each catching things
the previous level didn't:

**1. Unit tests (24/24 passing)** — cover decoding, flattening, signature
matching, scoring, and false-positive guardrails in isolation.

**2. Synthetic Wazuh validation** (`wazuh-logtest`) — hand-crafted JSON fed
directly into the Wazuh rule engine, confirming rules 100201/100202 fire
with correct MITRE mapping (T1190, T1059/T1083) on SQLi and command
injection payloads respectively.

**3. Full-chain live traffic test** — a real Flask listener
(`lab-testing/query_listener.py`) standing in for a QUERY-accepting
endpoint, hit with `lab-testing/query_test_fire.sh` sending actual HTTP
QUERY requests across the network from a separate host. Results:

| Test case | Payload | Risk Score | Matched | Wazuh Rule |
|---|---|---|---|---|
| Missing Content-Type | (empty) | — | — | 100200 |
| SQLi | `1 OR 1=1; DROP TABLE users;` | 80 | `sqli` | 100201 |
| NoSQLi | `{"$where": "..."}` | 35 | `nosqli` | 100201 |
| Path traversal (base64-encoded) | `../../etc/passwd` | 60 | `traversal` | 100202 |
| Deep nesting (behavioral) | 13-level nested JSON | 15 | — (depth-based) | 100204 |
| Benign control | `{"category":"laptops","sort":"price"}` | 0 | none | — (no alert) |

This confirms the full path — HTTP request → Flask → `normalize.py` →
structured JSON → Wazuh rule match — works correctly, and that the benign
control produces zero false positives. The NoSQLi key-scanning bug
mentioned above was actually caught at this stage: the initial version
scored the `$where` payload as 0/clean, because the scanner only checked
flattened JSON *values*, not *keys*, and NoSQL injection operators are
used as keys. Fixed and re-validated; the table above reflects the
corrected behavior.

## Why this design

**Recursive decoding, capped.** Attackers nest base64/hex/URL encoding to
dodge naive string matching. The decoder unwraps up to 5 layers — enough
to catch realistic obfuscation without letting a malicious input turn the
detector itself into a resource-exhaustion target.

**Signature + behavioral, not signature-only.** The Sigma injection rule
catches known-bad strings. The anomaly rule (`query_003`) catches payload
*shapes* — unusual size, deep nesting, high field cardinality — that have
no matching signature yet. This is the actual point of building detection
for a method the industry hasn't caught up on: signatures for QUERY-specific
attacks don't really exist in public rule sets yet, so a behavioral backstop
matters more here than it would for GET/POST.

**Composite risk score, not a single trigger.** `compute_risk_score()`
weights each signature category and folds in the z-score and JSON depth,
producing a 0–100 score meant to feed the same threshold-based routing used
in the SOAR playbooks (`score >= 75` → auto-contain candidate, lower →
analyst queue) — so this plugs into the existing pipeline rather than
requiring a parallel one.

**False positives are documented, not hidden.** Every Sigma rule lists
realistic FP sources (e.g. legitimate BI/reporting endpoints that accept
SQL-like filter syntax by design). The test suite includes a case proving
the detector doesn't fire on a benign `SELECT ... FROM` analytics query —
tuning evidence, the same pattern as the 58%→4% FP case study in
Detection-Content. Live testing added a second layer of this same
discipline: the benign control in the test-fire script consistently
scores 0 across every run, matching the unit-test guarantee under real
network conditions.

## Honest scope note

This has been validated end-to-end against a real HTTP listener and a
live Wazuh instance in an isolated lab (Wazuh + Shuffle + TheHive, same
environment as `soar-ir-pipeline`) — it is not a claim of production
enterprise deployment. If asked "has this seen production traffic," the
honest answer is: tested thoroughly in a controlled lab environment
against real (not simulated) HTTP requests and a real Wazuh rule engine,
not yet against live internet-facing traffic.

## Quick start

```bash
pip install pytest pyyaml
pytest tests/ -v

python3 src/normalize.py   # smoke test against a sample payload
```

## Lab testing setup

```bash
# On a host that will receive test QUERY traffic:
pip install flask
python lab-testing/query_listener.py   # listens on 0.0.0.0:8080

# From a separate host on the same network:
chmod +x lab-testing/query_test_fire.sh
./lab-testing/query_test_fire.sh http://<listener-host>:8080/api/search

# Check results:
#   - query_events.log on the listener host (raw normalize.py output)
#   - Wazuh dashboard, filtered to rule.id 100200-100204
#   - wazuh-logtest, fed a captured log line, to confirm rule matching directly
```

## Wiring into the existing SOAR pipeline

`analyze_query_body()` returns a dict via `.to_dict()` that's a drop-in
match for the JSON-webhook pattern the other 10 playbooks already expect.
`shuffle/pb11_query_method_playbook.json` implements this: Wazuh rules
100201-100204 route to a webhook, which enriches via AbuseIPDB, applies
the same `risk_score` threshold routing as PB-04, and creates a TheHive
case + Slack notification for anything scoring >= 40.

## Roadmap (next additions, in priority order)

1. Replace the placeholder containment app in PB-11's `node_05a` with the
   actual containment mechanism used by PB-01/PB-02
2. A Wazuh decoder + rule pair that calls `normalize.py` directly on
   ingest via a custom integration, rather than a standalone Flask listener
3. A small Postgres-backed analyst-disposition table so FP rate per rule
   can be tracked over time (the "self-tuning" feedback loop)
