import importlib.util
import io
import json
import sys
import threading
import types
import unittest
from pathlib import Path
from types import SimpleNamespace as Obj


def load_server_without_binary_ninja():
    root = Path(__file__).resolve().parents[1]
    for name in ("plugin", "plugin.api", "plugin.core", "plugin.server"):
        package = types.ModuleType(name)
        package.__path__ = [str(root / name.replace(".", "/"))]
        sys.modules[name] = package
    bn = types.ModuleType("binaryninja")
    setattr(bn, "log_info", lambda *_: None)
    setattr(bn, "log_error", lambda *_: None)
    sys.modules["binaryninja"] = bn
    endpoints = types.ModuleType("plugin.api.endpoints")

    class FakeEndpoints:
        def __init__(self, operations):
            self.operations = operations

        def list_binaries(self):
            return {"binaries": [{"view_id": "7"}]}

        def get_entry_points(self):
            return []

        def get_imports(self, offset, limit):
            return []

        def get_exports(self, offset, limit):
            return []

    setattr(endpoints, "BinaryNinjaEndpoints", FakeEndpoints)
    sys.modules[endpoints.__name__] = endpoints
    operations = types.ModuleType("plugin.core.binary_operations")
    setattr(operations, "BinaryOperations", object)
    sys.modules[operations.__name__] = operations
    config = types.ModuleType("plugin.core.config")
    setattr(config, "Config", object)
    sys.modules[config.__name__] = config
    path = root / "plugin" / "server" / "agent_http_server.py"
    spec = importlib.util.spec_from_file_location("plugin.server.agent_http_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server = load_server_without_binary_ninja()


class FakeOperations:
    def __init__(self):
        self._view_lock = threading.RLock()
        self._views_by_id = {"7": object()}
        self.current_view = Obj(is_valid_offset=lambda _: True)
        self.selected = None
        self.comment = None

    def select_view(self, binary_id):
        self.selected = binary_id
        return {"id": binary_id}

    def get_functions_page(self, query, offset, limit):
        return {
            "functions": [],
            "query": query,
            "offset": offset,
            "limit": limit,
            "next_offset": None,
            "truncated": False,
        }

    def get_comment(self, address):
        return self.comment

    def set_comment(self, address, comment):
        self.comment = comment or None
        return True


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.operations = FakeOperations()
        self.handler = server.AgentRequestHandler.__new__(server.AgentRequestHandler)
        self.handler.binary_ops = self.operations
        self.responses = []
        self.handler._send = lambda data, status=200: self.responses.append((status, data))

    def test_get_is_bound_to_explicit_binary(self):
        self.handler.path = "/agent/functions?binaryId=7&limit=2"
        self.handler.do_GET()
        status, data = self.responses[-1]
        self.assertEqual(status, 200)
        self.assertEqual(data["binary_id"], "7")
        self.assertEqual(self.operations.selected, "7")
        self.assertEqual(data["limit"], 2)

    def test_missing_or_closed_binary_is_an_error(self):
        self.handler.path = "/agent/functions?binaryId=8"
        self.handler.do_GET()
        self.assertEqual(self.responses[-1][0], 404)
        self.assertIsNone(self.operations.selected)

    def test_annotation_conflict_does_not_write(self):
        body = {
            "binary_id": "7",
            "action": "set_comment",
            "address": "0x1000",
            "expected_comment": "stale",
            "comment": "new",
        }
        encoded = json.dumps(body).encode()
        self.handler.path = "/agent/annotate"
        self.handler.headers = {"Content-Length": str(len(encoded))}
        self.handler.rfile = io.BytesIO(encoded)
        self.handler.do_POST()
        self.assertEqual(self.responses[-1][0], 409)
        self.assertIsNone(self.operations.comment)

    def test_annotation_success_reports_binary(self):
        body = {
            "binary_id": "7",
            "action": "set_comment",
            "address": "0x1000",
            "expected_comment": None,
            "comment": "new",
        }
        encoded = json.dumps(body).encode()
        self.handler.path = "/agent/annotate"
        self.handler.headers = {"Content-Length": str(len(encoded))}
        self.handler.rfile = io.BytesIO(encoded)
        self.handler.do_POST()
        self.assertEqual(self.responses[-1][0], 200)
        self.assertEqual(self.responses[-1][1]["binary_id"], "7")
        self.assertEqual(self.operations.comment, "new")


if __name__ == "__main__":
    unittest.main()
