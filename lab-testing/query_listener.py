"""
Minimal QUERY-method test listener for CLIENT01.

Accepts HTTP QUERY requests, runs the body through normalize.py's
analyze_query_body(), and writes the result as a JSON line to
query_events.log - the same format Wazuh's <decoded_as>json</decoded_as>
rules expect.

This is a test fixture for validating the detection pipeline end-to-end.
It is not a production web server - do not expose it beyond the lab.

Usage:
    pip install flask
    python query_listener.py
    # listens on 0.0.0.0:8080

Then point lab-testing/query_test_fire.sh at:
    http://<CLIENT01-ip>:8080/api/search
"""

import json
import logging
import sys
from pathlib import Path

from flask import Flask, request

# Import normalize.py from the project's src/ directory.
# Handles both layouts: the original repo (lab-testing/query_listener.py,
# src/ two levels up) and a flattened test deployment (query_listener.py
# and src/ as direct siblings, e.g. on a standalone test box).
_here = Path(__file__).resolve().parent
for _candidate in (_here / "src", _here.parent / "src"):
    if _candidate.exists():
        sys.path.insert(0, str(_candidate))
        break
else:
    raise ModuleNotFoundError(
        f"Could not find a 'src' directory containing normalize.py near {_here}. "
        f"Expected it either as a sibling folder or one level up."
    )
from normalize import analyze_query_body  # noqa: E402

app = Flask(__name__)

LOG_FILE = "query_events.log"

# A minimal handler that appends structured JSON lines Wazuh can ingest
# via a <localfile> pointed at this file with format="json".
logger = logging.getLogger("query_events")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


@app.route("/<path:endpoint>", methods=["QUERY"])
def handle_query(endpoint):
    raw_body = request.get_data()
    content_type = request.content_type or ""
    full_endpoint = f"/{endpoint}"

    result = analyze_query_body(raw_body, content_type, endpoint=full_endpoint)

    log_entry = result.to_dict()
    log_entry["http_method"] = "QUERY"
    log_entry["content_type"] = content_type
    log_entry["decoded_body"] = result.decoded_body
    log_entry["source_ip"] = request.remote_addr

    logger.info(json.dumps(log_entry))

    return {"status": "received", "risk_score": result.risk_score}, 200


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    print(f"QUERY test listener starting on 0.0.0.0:8080")
    print(f"Logging events to: {Path(LOG_FILE).resolve()}")
    print(f"Point lab-testing/query_test_fire.sh at: http://<this-host>:8080/api/search")
    app.run(host="0.0.0.0", port=8080, threaded=True)
