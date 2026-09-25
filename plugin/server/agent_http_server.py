"""Local, serialized HTTP adapter for the agent-facing MCP bridge."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import binaryninja as bn

from ..api.endpoints import BinaryNinjaEndpoints
from ..core.binary_operations import BinaryOperations
from ..core.config import Config


class ConflictError(Exception):
    def __init__(self, message: str, current: Any):
        super().__init__(message)
        self.current = current


class AgentRequestHandler(BaseHTTPRequestHandler):
    binary_ops: BinaryOperations

    def log_message(self, format: str, *args: Any) -> None:
        bn.log_info(format % args)

    def _send(self, data: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _fail(self, error: Exception) -> None:
        if isinstance(error, ConflictError):
            self._send({"error": str(error), "current": error.current}, 409)
        elif isinstance(error, LookupError):
            self._send({"error": str(error)}, 404)
        elif isinstance(error, (ValueError, TypeError, json.JSONDecodeError)):
            self._send({"error": str(error)}, 400)
        else:
            bn.log_error(f"Agent request failed: {error}")
            self._send({"error": str(error)}, 500)

    @staticmethod
    def _address(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError("address must be hex (0x...) or decimal")
        if isinstance(value, str):
            address = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        else:
            address = value
        if address < 0:
            raise ValueError("address must be non-negative")
        return address

    @staticmethod
    def _bounded_page(params: dict[str, str]) -> tuple[int, int]:
        offset = int(params.get("offset", "0"))
        limit = int(params.get("limit", "100"))
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("offset must be >= 0 and limit must be 1..200")
        return offset, limit

    @staticmethod
    def _required(params: dict[str, Any], key: str) -> str:
        value = params.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} is required")
        return value

    def _select(self, binary_id: str) -> None:
        if binary_id not in self.binary_ops._views_by_id:
            raise LookupError("Binary view is closed or unknown; call list_binaries")
        if self.binary_ops.select_view(binary_id) is None:
            raise LookupError("Binary view is closed or unknown; call list_binaries")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        try:
            if path == "/binaries":
                with self.binary_ops._view_lock:
                    data = BinaryNinjaEndpoints(self.binary_ops).list_binaries()
                self._send(data)
                return
            if not path.startswith("/agent/"):
                raise LookupError("Unknown route")
            binary_id = self._required(params, "binaryId")
            with self.binary_ops._view_lock:
                self._select(binary_id)
                data = self._read(path, params)
            self._send({"binary_id": binary_id, **data})
        except Exception as error:
            self._fail(error)

    def _read(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        ops = self.binary_ops
        endpoints = BinaryNinjaEndpoints(ops)
        offset, limit = self._bounded_page(params)
        if path == "/agent/identity":
            return ops.get_binary_identity(params.get("includeSha256") == "true")
        if path == "/agent/functions":
            return ops.get_functions_page(params.get("query", ""), offset, limit)
        if path == "/agent/strings":
            return ops.get_strings_page(params.get("query", ""), offset, limit)
        if path == "/agent/function":
            info = ops.get_function_info(self._required(params, "identifier"))
            if info is None:
                raise LookupError("Function not found")
            return info
        if path == "/agent/functionAt":
            return ops.get_functions_containing(self._required(params, "address"))
        if path == "/agent/relatedFunctions":
            return ops.get_related_functions_page(
                self._required(params, "identifier"),
                self._required(params, "relation"),
                offset,
                limit,
            )
        if path == "/agent/il":
            return ops.get_function_il_page(
                self._required(params, "identifier"),
                params.get("view", "hlil"),
                params.get("ssa") == "true",
                offset,
                limit,
            )
        if path == "/agent/decompile":
            return ops.get_function_decompiled_page(
                self._required(params, "identifier"), offset, limit
            )
        if path == "/agent/disassembly":
            return ops.get_function_disassembly_page(
                self._required(params, "identifier"), offset, limit
            )
        if path == "/agent/basicBlocks":
            return ops.get_function_basic_blocks_page(
                self._required(params, "identifier"), offset, limit
            )
        if path == "/agent/stackFrame":
            return endpoints.get_stack_frame_page(
                self._required(params, "identifier"), offset, limit
            )
        if path == "/agent/xrefs":
            return ops.get_xrefs_to_page(
                self._required(params, "address"),
                offset,
                limit,
                params.get("includeCode", "true") == "true",
                params.get("includeData", "true") == "true",
            )
        if path == "/agent/bytes":
            return ops.read_bytes_page(
                self._required(params, "address"), int(params.get("length", "256"))
            )
        if path == "/agent/comment":
            address = self._address(self._required(params, "address"))
            current_view = ops.current_view
            if current_view is None:
                raise RuntimeError("No binary loaded")
            if not current_view.is_valid_offset(address):
                raise ValueError("address is not valid in this view")
            return {"address": hex(address), "comment": ops.get_comment(address)}
        if path == "/agent/entryPoints":
            return {"entry_points": endpoints.get_entry_points()}
        if path in ("/agent/imports", "/agent/exports"):
            kind = "imports" if path.endswith("imports") else "exports"
            return ops.get_symbols_page(kind, offset, limit)
        if path == "/agent/memoryMap":
            kind = self._required(params, "kind")
            if kind == "segments":
                rows = ops.get_segments(offset, limit + 1)
            elif kind == "sections":
                rows = ops.get_sections(offset, limit + 1)
            else:
                raise ValueError("kind must be segments or sections")
            for row in rows:
                if row.get("name") is not None:
                    row["name"] = str(row["name"])
                if "flags" in row:
                    row["flags"] = [str(flag) for flag in row["flags"]]
            more = len(rows) > limit
            return {
                "kind": kind,
                "regions": rows[:limit],
                "offset": offset,
                "limit": limit,
                "next_offset": offset + limit if more else None,
                "truncated": more,
            }
        raise LookupError("Unknown route")

    def do_POST(self) -> None:
        try:
            if urlparse(self.path).path != "/agent/annotate":
                raise LookupError("Unknown route")
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 65536:
                raise ValueError("JSON body must be 1..65536 bytes")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
            binary_id = self._required(data, "binary_id")
            with self.binary_ops._view_lock:
                self._select(binary_id)
                result = self._annotate(data)
            self._send({"binary_id": binary_id, **result})
        except Exception as error:
            self._fail(error)

    def _annotate(self, data: dict[str, Any]) -> dict[str, Any]:
        ops = self.binary_ops
        address = self._address(data.get("address"))
        action = data.get("action")
        if action == "rename_function":
            current_view = ops.current_view
            if current_view is None:
                raise RuntimeError("No binary loaded")
            function = current_view.get_function_at(address)
            if function is None:
                raise LookupError("Function not found at start address")
            expected = self._required(data, "expected_name")
            new_name = self._required(data, "new_name")
            if len(new_name) > 256:
                raise ValueError("new_name is too long")
            if function.name != expected:
                raise ConflictError("Function name changed", function.name)
            if not ops.rename_function(address, new_name):
                raise RuntimeError("Rename failed")
            updated = current_view.get_function_at(address)
            if updated is None or updated.name != new_name:
                raise RuntimeError("Rename could not be verified")
            return {
                "success": True,
                "action": action,
                "address": hex(address),
                "old_name": expected,
                "new_name": new_name,
            }
        if action == "set_comment":
            comment = data.get("comment")
            if not isinstance(comment, str) or len(comment) > 16000:
                raise ValueError("comment must be a string of at most 16000 characters")
            if "expected_comment" not in data or not isinstance(
                data["expected_comment"], (str, type(None))
            ):
                raise ValueError("expected_comment must be a string or null")
            current_view = ops.current_view
            if current_view is None:
                raise RuntimeError("No binary loaded")
            if not current_view.is_valid_offset(address):
                raise ValueError("address is not valid in this view")
            current = ops.get_comment(address)
            if current != data["expected_comment"]:
                raise ConflictError("Comment changed", current)
            if not ops.set_comment(address, comment):
                raise RuntimeError("Comment update failed")
            if ops.get_comment(address) != (comment or None):
                raise RuntimeError("Comment update could not be verified")
            return {"success": True, "action": action, "address": hex(address), "comment": comment}
        raise ValueError("action must be rename_function or set_comment")


class MCPServer:
    def __init__(self, config: Config):
        self.config = config
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.binary_ops = BinaryOperations(config.binary_ninja)

    def start(self) -> None:
        handler = type(
            "AgentRequestHandlerWithOps", (AgentRequestHandler,), {"binary_ops": self.binary_ops}
        )
        self.server = HTTPServer((self.config.server.host, self.config.server.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        bn.log_info(
            f"Agent HTTP server started on {self.config.server.host}:{self.config.server.port}"
        )

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            if self.thread is not None:
                self.thread.join()
            self.thread = None
            self.server = None
            bn.log_info("Agent HTTP server stopped")
