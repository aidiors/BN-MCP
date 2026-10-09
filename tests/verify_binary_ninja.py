"""Optional live SDK smoke check. Loads only the repository's disposable example view."""

import argparse
import importlib
import json
import os
import sys
import types
from http.client import HTTPConnection
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sdk-path", type=Path, help="Binary Ninja installation's python directory"
    )
    parser.add_argument(
        "--binary", type=Path, help="Optional file to open in a separate temporary view"
    )
    args = parser.parse_args()
    if args.sdk_path:
        sys.path.insert(0, str(args.sdk_path))
    os.environ["BN_DISABLE_USER_PLUGINS"] = "1"
    bn = importlib.import_module("binaryninja")
    root = Path(__file__).resolve().parents[1]
    # Import project modules under a separate namespace to bypass GUI initialization.
    for name in (
        "bn_mcp_live",
        "bn_mcp_live.api",
        "bn_mcp_live.core",
        "bn_mcp_live.server",
        "bn_mcp_live.utils",
    ):
        package = types.ModuleType(name)
        suffix = name.removeprefix("bn_mcp_live").lstrip(".")
        package.__path__ = [str(root / "plugin" / suffix.replace(".", "/"))]
        sys.modules[name] = package
    config_module = importlib.import_module("bn_mcp_live.core.config")
    server_module = importlib.import_module("bn_mcp_live.server.agent_http_server")
    settings = config_module.Config()
    settings.server.host, settings.server.port = "127.0.0.1", 0
    settings.server.auth_token = ""
    settings.server.read_timeout = 5
    mcp = server_module.MCPServer(settings)
    view = bn.load(str(args.binary or root / "example" / "chal"))
    try:
        mcp.start()
        assert mcp.server is not None
        port = mcp.server.server_port
        view_id = mcp.binary_ops.register_view(view, keep_alive=True)
        mcp.binary_ops.current_view = view
        raw = view.file.get_view_of_type("Raw")
        if raw is not None:
            raw_id = mcp.binary_ops.register_view(raw, keep_alive=True)
            assert raw_id != view_id, "Different native views share an ID"
            assert mcp.binary_ops.register_view(view.file.get_view_of_type("Raw")) == raw_id
            mcp.binary_ops.current_view = raw
        function = next(iter(view.functions))
        address = hex(function.start)

        def request(path, body=None, expected=200):
            connection = HTTPConnection("127.0.0.1", port, timeout=30)
            try:
                connection.request(
                    "POST" if body is not None else "GET",
                    path,
                    json.dumps(body).encode() if body is not None else None,
                    {"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                data = json.loads(response.read())
                assert response.status == expected, (path, response.status, data)
                return data
            finally:
                connection.close()

        request("/binaries")
        routes = [
            "identity",
            "functions",
            "strings",
            f"function&identifier={address}",
            f"functionAt&address={address}",
            f"relatedFunctions&identifier={address}&relation=callers",
            f"il&identifier={address}",
            f"decompile&identifier={address}",
            f"disassembly&identifier={address}",
            f"basicBlocks&identifier={address}",
            f"stackFrame&identifier={address}",
            f"xrefs&address={address}",
            f"bytes&address={address}&length=16",
            f"comment&address={address}",
            "entryPoints",
            "memoryMap&kind=segments",
            "memoryMap&kind=sections",
            "imports",
            "exports",
        ]
        for route in routes:
            operation, _, params = route.partition("&")
            result = request(f"/agent/{operation}?binaryId={view_id}&limit=1&{params}")
            assert result["binary_id"] == view_id
        assert mcp.binary_ops.current_view is (raw if raw is not None else view)
        request("/agent/functions?binaryId=0", expected=404)
        # Annotations are temporary analysis state on this separately loaded example.
        # restore them, and never save a database or alter the original file bytes.
        old_name = function.name
        body = {
            "binary_id": view_id,
            "address": address,
            "action": "rename_function",
            "expected_name": old_name,
            "new_name": "__mcp_smoke_test",
        }
        request("/agent/annotate", body)
        body.update(expected_name="__mcp_smoke_test", new_name=old_name)
        request("/agent/annotate", body)
        old_comment = view.get_comment_at(function.start) or None
        body = {
            "binary_id": view_id,
            "address": address,
            "action": "set_comment",
            "expected_comment": old_comment,
            "comment": "temporary MCP smoke check",
        }
        request("/agent/annotate", body)
        body.update(expected_comment="temporary MCP smoke check", comment=old_comment or "")
        request("/agent/annotate", body)
        mcp.binary_ops.unregister_file(view.file)
        assert request("/binaries")["binaries"] == []
        request(f"/agent/functions?binaryId={view_id}", expected=404)
        print(f"Live SDK {bn.core_version()}: all agent routes and both annotations passed")
    finally:
        mcp.stop()
        view.file.close()


if __name__ == "__main__":
    main()
