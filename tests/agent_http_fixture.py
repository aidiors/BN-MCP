"""Run the HTTP backend with SDK test doubles for the TypeScript integration test."""

import json
import sys

from agent_test_support import HTTPFixture, populated_view

fixture = HTTPFixture(token="test-only-token", read_timeout=2)
view = populated_view()
view_id = fixture.mcp.binary_ops.register_view(view)
try:
    print(json.dumps({"port": fixture.port, "view_id": view_id}), flush=True)
    sys.stdin.read()
finally:
    fixture.close()
