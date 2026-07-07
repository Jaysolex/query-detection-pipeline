"""
QUERY Body Normalization & Detection Service
=============================================

Ingests raw HTTP QUERY request bodies (RFC 10008), recursively decodes
common encodings, flattens nested JSON, and scores the result against
known injection patterns and a per-endpoint statistical baseline.

This is a detection/monitoring component: it inspects traffic that has
already reached the gateway in order to flag and score it for a SOC
pipeline (e.g. forwarded to Wazuh/Shuffle as in soar-ir-pipeline). It
does not construct or send attack payloads.

Usage:
    from normalize import analyze_query_body
    result = analyze_query_body(raw_body_bytes, content_type, endpoint="/search")
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import statistics
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from typing import Any

MAX_DECODE_DEPTH = 5          # hard cap so recursive decoding can't be turned into a decode-bomb DoS on the pipeline itself
MAX_JSON_DEPTH = 50           # sanity cap for nesting inspection
BASELINE_WINDOW = 30          # rolling window, in "samples", used for z-score baselining

# --- Signature sets -------------------------------------------------------
# Kept intentionally narrow and well-known; this mirrors public detection
# content (e.g. OWASP CRS-style indicators) and is meant for pattern
# matching against inbound traffic, not for generating payloads.

SQLI_PATTERNS = [
    r"union\s+select",
    r"\bor\b\s+1\s*=\s*1",
    r"drop\s+table",
    r"--\s*$",
    r"'\s*or\s*'1'\s*=\s*'1",
]

NOSQLI_PATTERNS = [
    r"\$where",
    r"\$regex",
    r"\$gt\b",
    r"\$ne\b",
]

CMDI_PATTERNS = [
    r";\s*cat\s",
    r"&&\s*whoami",
    r"\|\s*nc\s",
    r"`[^`]+`",
]

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.%2f",
    r"/etc/passwd",
]

XSS_PATTERNS = [
    r"<script",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
]

_COMPILED = {
    "sqli": [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS],
    "nosqli": [re.compile(p, re.IGNORECASE) for p in NOSQLI_PATTERNS],
    "cmdi": [re.compile(p, re.IGNORECASE) for p in CMDI_PATTERNS],
    "traversal": [re.compile(p, re.IGNORECASE) for p in TRAVERSAL_PATTERNS],
    "xss": [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS],
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class AnalysisResult:
    endpoint: str
    decoded_body: str
    flattened_fields: dict[str, Any] = field(default_factory=dict)
    matches: dict[str, list[str]] = field(default_factory=dict)
    body_size_bytes: int = 0
    json_max_depth: int = 0
    field_count: int = 0
    entropy: float = 0.0
    z_score: float | None = None
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "body_size_bytes": self.body_size_bytes,
            "json_max_depth": self.json_max_depth,
            "field_count": self.field_count,
            "entropy": round(self.entropy, 3),
            "z_score": None if self.z_score is None else round(self.z_score, 3),
            "matches": self.matches,
            "risk_score": self.risk_score,
        }


class EndpointBaseline:
    """Rolling per-endpoint baseline for body size / depth / field count.

    In production this would be backed by Redis or a small Postgres table
    keyed by endpoint (see the feedback-loop table in the pipeline design).
    Kept in-memory here so the module is self-contained and testable.
    """

    def __init__(self, window: int = BASELINE_WINDOW):
        self.window = window
        self._samples: dict[str, deque[float]] = {}

    def update_and_score(self, endpoint: str, value: float) -> float | None:
        history = self._samples.setdefault(endpoint, deque(maxlen=self.window))
        z = None
        if len(history) >= 5:
            mean = statistics.mean(history)
            raw_stdev = statistics.pstdev(history)
            # Floor stdev relative to the mean (min 1.0 absolute) so that a
            # perfectly flat history doesn't turn a trivial fluctuation into
            # an astronomical z-score. This mirrors how you'd guard a
            # coefficient-of-variation calc against a zero-variance window.
            stdev = max(raw_stdev, mean * 0.02, 1.0)
            z = (value - mean) / stdev
        history.append(value)
        return z


_DEFAULT_BASELINE = EndpointBaseline()


def _looks_like_base64(s: str) -> bool:
    if len(s) < 8 or len(s) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s))


def _try_decode_layer(s: str) -> str | None:
    """Attempt one layer of base64 / hex / URL decoding. Returns None if
    no decoding applies, to signal the recursion should stop."""
    # URL decoding
    unquoted = urllib.parse.unquote_plus(s)
    if unquoted != s:
        return unquoted

    # Base64
    if _looks_like_base64(s):
        try:
            decoded = base64.b64decode(s, validate=True)
            return decoded.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            pass

    # Hex
    if _HEX_RE.match(s) and len(s) % 2 == 0 and len(s) >= 8:
        try:
            decoded = bytes.fromhex(s)
            text = decoded.decode("utf-8", errors="ignore")
            if text.isprintable():
                return text
        except ValueError:
            pass

    return None


def recursive_decode(s: str, depth: int = 0) -> str:
    """Recursively unwrap URL/base64/hex encoding up to MAX_DECODE_DEPTH."""
    if depth >= MAX_DECODE_DEPTH:
        return s
    decoded = _try_decode_layer(s)
    if decoded is None or decoded == s:
        return s
    return recursive_decode(decoded, depth + 1)


def flatten_json(obj: Any, prefix: str = "", depth: int = 0, out: dict[str, Any] | None = None) -> tuple[dict[str, Any], int]:
    """Recursively flattens nested JSON into dotted-key form and returns
    (flattened_dict, max_depth_seen)."""
    if out is None:
        out = {}
    if depth > MAX_JSON_DEPTH:
        out[prefix or "__truncated__"] = "<max depth exceeded>"
        return out, depth

    max_depth = depth
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            _, d = flatten_json(v, key, depth + 1, out)
            max_depth = max(max_depth, d)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            _, d = flatten_json(v, key, depth + 1, out)
            max_depth = max(max_depth, d)
    else:
        out[prefix or "__root__"] = obj
        max_depth = depth

    return out, max_depth


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def scan_signatures(text: str) -> dict[str, list[str]]:
    matches: dict[str, list[str]] = {}
    for category, patterns in _COMPILED.items():
        hits = []
        for pattern in patterns:
            found = pattern.findall(text)
            if found:
                hits.append(pattern.pattern)
        if hits:
            matches[category] = hits
    return matches


def compute_risk_score(matches: dict[str, list[str]], z_score: float | None, json_max_depth: int) -> int:
    """Simple weighted composite; mirrors the scoring pattern used in
    soar-ir-pipeline's playbooks so this can feed the same downstream
    routing logic (score >= 75 -> auto-contain candidate, etc)."""
    score = 0
    weights = {"sqli": 40, "nosqli": 35, "cmdi": 45, "traversal": 30, "xss": 25}
    for category, patterns in matches.items():
        score += weights.get(category, 10) * len(patterns)

    if z_score is not None and z_score > 3.5:
        score += 20
    if json_max_depth > 12:
        score += 15

    return min(score, 100)


def analyze_query_body(
    raw_body: bytes,
    content_type: str,
    endpoint: str,
    baseline: EndpointBaseline | None = None,
) -> AnalysisResult:
    baseline = baseline or _DEFAULT_BASELINE
    body_text = raw_body.decode("utf-8", errors="replace")

    # Recursively decode the raw text itself (covers bodies that are
    # e.g. a base64 blob rather than valid JSON).
    decoded_text = recursive_decode(body_text)

    flattened: dict[str, Any] = {}
    max_depth = 0
    if "json" in content_type.lower():
        try:
            parsed = json.loads(decoded_text)
            flattened, max_depth = flatten_json(parsed)
            # Also recursively decode each leaf value, since payloads are
            # often nested one layer inside an otherwise-valid JSON body.
            flattened = {k: recursive_decode(v) if isinstance(v, str) else v for k, v in flattened.items()}
        except json.JSONDecodeError:
            flattened = {"__unparsed__": decoded_text}
    else:
        flattened = {"__raw__": decoded_text}

    # Scan BOTH keys and values: NoSQL operators like $where/$regex/$gt/$ne
    # are used as JSON KEYS, not values - scanning values alone misses them
    # entirely. Fixed after live lab testing showed a $where payload scoring
    # 0 when it should have matched (see docs/PB-11_README.md testing notes).
    scan_target = " ".join(f"{k} {v}" for k, v in flattened.items())
    matches = scan_signatures(scan_target)

    result = AnalysisResult(
        endpoint=endpoint,
        decoded_body=decoded_text,
        flattened_fields=flattened,
        matches=matches,
        body_size_bytes=len(raw_body),
        json_max_depth=max_depth,
        field_count=len(flattened),
        entropy=shannon_entropy(decoded_text),
    )

    result.z_score = baseline.update_and_score(endpoint, float(result.body_size_bytes))
    result.risk_score = compute_risk_score(matches, result.z_score, max_depth)

    return result


if __name__ == "__main__":
    # Minimal smoke test / demo — not a substitute for tests/test_normalize.py
    sample = json.dumps({
        "filter": {"and": [{"field": "name", "op": "eq", "value": "UNION SELECT password FROM users--"}]},
        "note": base64.b64encode(b"../../etc/passwd").decode(),
    }).encode()

    analysis = analyze_query_body(sample, "application/json", endpoint="/api/search")
    print(json.dumps(analysis.to_dict(), indent=2))
