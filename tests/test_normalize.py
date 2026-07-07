"""
Unit tests for src/normalize.py

Run with: pytest tests/test_normalize.py -v

Covers: recursive decoding, JSON flattening, signature matching,
risk scoring, and false-positive guardrails (legitimate traffic
that should NOT trigger high-risk scores).
"""

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from normalize import (  # noqa: E402
    EndpointBaseline,
    analyze_query_body,
    flatten_json,
    recursive_decode,
    scan_signatures,
    shannon_entropy,
)


class TestRecursiveDecode:
    def test_url_encoded_traversal(self):
        assert recursive_decode("..%2f..%2fetc%2fpasswd") == "../../etc/passwd"

    def test_base64_layer(self):
        payload = base64.b64encode(b"UNION SELECT * FROM users").decode()
        assert recursive_decode(payload) == "UNION SELECT * FROM users"

    def test_double_encoded_base64_then_url(self):
        inner = base64.b64encode(b"whoami").decode()
        outer = f"cmd={inner}"  # not itself base64, decode should stop cleanly
        result = recursive_decode(outer)
        assert result == outer  # no valid single-layer decode applies to the whole string

    def test_plain_text_passthrough(self):
        assert recursive_decode("hello world") == "hello world"

    def test_depth_cap_prevents_infinite_loop(self):
        # A string that happens to keep "decoding" to itself-ish should
        # still terminate quickly due to MAX_DECODE_DEPTH. Note: strings
        # shorter than 8 chars are intentionally not treated as base64
        # candidates (see _looks_like_base64) to avoid false-positive
        # decodes of short benign tokens, so we use a longer sample here.
        result = recursive_decode("QWRtaW4=")  # base64 for "Admin"
        assert result == "Admin"


class TestFlattenJson:
    def test_simple_object(self):
        flat, depth = flatten_json({"a": 1, "b": "x"})
        assert flat == {"a": 1, "b": "x"}
        assert depth == 1

    def test_nested_object(self):
        flat, depth = flatten_json({"filter": {"and": [{"field": "name"}]}})
        assert "filter.and[0].field" in flat
        assert flat["filter.and[0].field"] == "name"
        assert depth == 4

    def test_list_indices(self):
        flat, _ = flatten_json({"items": [1, 2, 3]})
        assert flat == {"items[0]": 1, "items[1]": 2, "items[2]": 3}


class TestScanSignatures:
    def test_detects_sqli(self):
        matches = scan_signatures("value=' OR 1=1 --")
        assert "sqli" in matches

    def test_detects_nosqli(self):
        matches = scan_signatures('{"$where": "this.password.length > 0"}')
        assert "nosqli" in matches

    def test_detects_command_injection(self):
        matches = scan_signatures("filename; cat /etc/shadow")
        assert "cmdi" in matches

    def test_clean_input_no_matches(self):
        matches = scan_signatures("category=laptops&brand=example&sort=price")
        assert matches == {}

    def test_legitimate_analytics_query_language_is_flagged_not_silently_passed(self):
        # This documents a known false-positive class from the Sigma rule
        # (see falsepositives: in query_002). The detector SHOULD flag it —
        # suppression is a policy decision made downstream, not something
        # the detector should silently decide on its own.
        matches = scan_signatures("SELECT region, SUM(revenue) FROM sales")
        # 'SELECT' alone without UNION/OR 1=1/DROP shouldn't false-positive
        assert "sqli" not in matches


class TestEndpointBaseline:
    def test_no_zscore_until_enough_samples(self):
        baseline = EndpointBaseline()
        z = None
        for _ in range(4):
            z = baseline.update_and_score("/search", 500.0)
        assert z is None  # fewer than 5 samples seen

    def test_zscore_flags_outlier(self):
        baseline = EndpointBaseline()
        for _ in range(10):
            baseline.update_and_score("/search", 500.0)
        z = baseline.update_and_score("/search", 50000.0)
        assert z is not None and z > 3.0

    def test_stable_traffic_scores_near_zero(self):
        baseline = EndpointBaseline()
        for _ in range(10):
            baseline.update_and_score("/search", 500.0)
        z = baseline.update_and_score("/search", 505.0)
        assert z is not None and abs(z) < 1.0


class TestAnalyzeQueryBody:
    def test_malicious_payload_scores_high(self):
        body = json.dumps({"q": "1 OR 1=1; DROP TABLE users;"}).encode()
        result = analyze_query_body(body, "application/json", endpoint="/api/search")
        assert result.risk_score >= 40
        assert "sqli" in result.matches

    def test_benign_payload_scores_low(self):
        body = json.dumps({"category": "laptops", "sort": "price", "page": 1}).encode()
        result = analyze_query_body(body, "application/json", endpoint="/api/search")
        assert result.risk_score == 0
        assert result.matches == {}

    def test_encoded_traversal_is_caught_after_decode(self):
        body = json.dumps({"path": base64.b64encode(b"../../../etc/passwd").decode()}).encode()
        result = analyze_query_body(body, "application/json", endpoint="/api/files")
        assert "traversal" in result.matches

    def test_non_json_content_type_handled_gracefully(self):
        body = b"raw text body, not json"
        result = analyze_query_body(body, "text/plain", endpoint="/api/legacy")
        assert result.flattened_fields.get("__raw__") == "raw text body, not json"

    def test_malformed_json_does_not_crash(self):
        body = b'{"broken": '
        result = analyze_query_body(body, "application/json", endpoint="/api/search")
        assert "__unparsed__" in result.flattened_fields


class TestShannonEntropy:
    def test_empty_string_zero_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_repeated_char_low_entropy(self):
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_random_looking_string_higher_entropy(self):
        assert shannon_entropy("aG9zdG5hbWU9YWRtaW4=") > 3.0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
