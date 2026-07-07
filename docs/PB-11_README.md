# PB-11: HTTP QUERY Method Injection & Anomaly Response

## Overview

Extends the 10-playbook suite to cover HTTP QUERY (RFC 10008) traffic —
a method with no existing public detection/response content as of this
writing. Wired to the same Wazuh -> Shuffle -> TheHive pattern as PB-01
through PB-10.

| Field | Value |
|---|---|
| Severity | High (signature match) / Medium (behavioral only) |
| Auto-Contain | Yes (score >= 75), matching PB-01/PB-04 threshold convention |
| Key Enrichment | AbuseIPDB (source IP reputation), internal endpoint baseline (z-score) |
| MITRE | T1190 (Exploit Public-Facing Application), T1059 (Command/Injection), T1595.002 (Vulnerability Scanning) |
| Wazuh Rule IDs | 100200-100204 |

## Trigger Conditions

Wazuh rules 100200-100204 (see `wazuh/query_rules.xml`) fire on:
- **100200**: QUERY request missing/invalid Content-Type (protocol compliance, low severity — logged, not escalated)
- **100201**: SQLi/NoSQLi signature in QUERY body
- **100202**: Command injection / path traversal signature in QUERY body
- **100203/100204**: Anomalous body shape (z-score or nesting depth) — behavioral, no signature match required

Rules 100201/100202 are the primary triggers for this playbook. Rule
100200 is informational-only (logged, not routed to Shuffle) since a
missing Content-Type alone is a compliance issue, not an attack
indicator — routing it into the same auto-contain path as a confirmed
SQLi hit would misrepresent its severity.

## Workflow Steps

1. **Webhook ingestion** — Wazuh forwards rule 100201/100202/100203/100204
   alerts as JSON to a dedicated Shuffle webhook (see `shuffle/pb11_query_method_playbook.json`)
2. **Enrichment** — source IP checked against AbuseIPDB; if the endpoint
   has baseline history, the z-score from `normalize.py` is already
   embedded in the alert payload (no extra enrichment call needed for
   the behavioral signal, unlike PB-02/PB-05 which call MaxMind live)
3. **Composite scoring** — reuses the `risk_score` computed by
   `normalize.py` at detection time; Shuffle does not recompute it,
   only applies the routing threshold
4. **Routing**:
   - `risk_score >= 75` -> auto-contain: block source IP at
     gateway/WAF (or Wazuh active response if configured), create
     TheHive case tagged `CONFIDENTIAL`, notify Slack `#soc-critical`
   - `risk_score 40-74` -> analyst queue: create TheHive case, no
     auto-containment, notify Slack `#soc-alerts`
   - `risk_score < 40` -> log only, no case created (avoids alert
     fatigue from the behavioral rule's lower-confidence hits)
5. **TheHive case fields**:
   - Title: `QUERY Method Alert - {endpoint} - Score {risk_score}`
   - Severity: mapped from risk_score per the routing table above
   - Observables: source IP, endpoint, decoded body excerpt (first
     200 chars only — full body stays in Wazuh, not duplicated into
     the case to avoid bloating TheHive with raw payloads)
   - Tags: `rfc10008`, `query-method`, plus whichever signature
     category matched (`sqli`, `nosqli`, `cmdi`, `traversal`, `behavioral`)

## False Positive Handling

Matches the FP-reduction pattern from `evidence/fp_reduction_case_study.md`:
analytics/BI endpoints that legitimately accept SQL-like filter syntax
are the primary known FP source (documented in
`sigma/query_002_body_injection_signatures.yml`). Recommended tuning
path if this fires on legitimate traffic: add an endpoint allowlist to
the Shuffle workflow's initial filter step, rather than weakening the
Wazuh rule itself — keeps the detection broad while suppressing known-
benign sources at the orchestration layer, where it's easier to review
and revert.

## Testing

Use `lab-testing/query_test_fire.sh` against a test endpoint to confirm
rules 100201-100204 fire in Wazuh, then confirm the Shuffle webhook
receives the forwarded alert and creates the expected TheHive case.
The 6th test case (benign control) should produce zero Wazuh alerts and
therefore zero Shuffle/TheHive activity — that's the FP-guardrail proof
for this playbook, same role as the "SELECT ... FROM analytics query"
unit test in `tests/test_normalize.py`.
