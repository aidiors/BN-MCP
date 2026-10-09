"""Local, serialized HTTP adapter for the agent-facing MCP bridge."""

from __future__ import annotations

import hmac
import json
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
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


class ServerStoppingError(Exception):
    pass


class RequestRejected(Exception):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


class BoundedThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 64

    def __init__(
        self,
        server_address,
        request_handler_class,
        max_workers: int = 16,
        read_timeout: float = 5.0,
        shutdown_timeout: float = 1.0,
        auth_token: str = "",
    ):
        self._request_slots = threading.BoundedSemaphore(max_workers)
        self._connections_lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._workers: set[threading.Thread] = set()
        self._operations_lock = threading.Lock()
        self.stopping = threading.Event()
        self.read_timeout = read_timeout
        self.shutdown_timeout = shutdown_timeout
        self.auth_token = auth_token
        super().__init__(server_address, request_handler_class)

    def process_request(self, request, client_address) -> None:
        if self.stopping.is_set() or not self._request_slots.acquire(blocking=False):
            try:
                request.settimeout(self.read_timeout)
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\nRetry-After: 1\r\n"
                    b"Connection: close\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        with self._connections_lock:
            if self.stopping.is_set():
                self._request_slots.release()
                self.shutdown_request(request)
                return
            self._connections.add(request)
        try:
            request.settimeout(self.read_timeout)
            super().process_request(request, client_address)
        except Exception:
            with self._connections_lock:
                self._connections.discard(request)
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        worker = threading.current_thread()
        with self._connections_lock:
            self._workers.add(worker)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._connections_lock:
                self._connections.discard(request)
                self._workers.discard(worker)
            self._request_slots.release()

    @contextmanager
    def operation(self):
        # Waiting clients must recheck cancellation instead of executing a queued write.
        deadline = time.monotonic() + 25.0
        while not self._operations_lock.acquire(timeout=0.05):
            if self.stopping.is_set():
                raise ServerStoppingError("Server is stopping")
            if time.monotonic() >= deadline:
                raise ServerStoppingError("Server is busy. Retry after the current operation.")
        try:
            if self.stopping.is_set():
                raise ServerStoppingError("Server is stopping")
            yield
        finally:
            self._operations_lock.release()

    def begin_shutdown(self):
        self.stopping.set()
        with self._connections_lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def wait_workers(self, timeout: float | None = None) -> bool:
        deadline = time.monotonic() + timeout if timeout is not None else None
        while True:
            with self._connections_lock:
                workers = list(self._workers)
                has_connections = bool(self._connections)
            if not workers and not has_connections:
                return True
            if not workers:
                time.sleep(0.01)
            for worker in workers:
                remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
                worker.join(remaining)
            if deadline is not None and time.monotonic() >= deadline:
                return False

    def server_close(self):
        self.begin_shutdown()
        super().server_close()
        self.wait_workers(self.shutdown_timeout)


class AgentRequestHandler(BaseHTTPRequestHandler):
    binary_ops: BinaryOperations
    server: BoundedThreadingHTTPServer

    def setup(self):
        super().setup()
        self._read_deadline = time.monotonic() + self.server.read_timeout
        self._read_expired = False
        self._read_timer = threading.Timer(self.server.read_timeout, self._expire_read)
        self._read_timer.daemon = True
        self._read_timer.start()

    def _expire_read(self):
        self._read_expired = True
        try:
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def _finish_read(self):
        self._read_timer.cancel()
        if self._read_expired or time.monotonic() >= self._read_deadline:
            raise TimeoutError("Request read deadline exceeded")

    def finish(self):
        self._read_timer.cancel()
        try:
            super().finish()
        except OSError:
            pass

    def handle(self):
        try:
            super().handle()
        except OSError:
            # Peer disconnects and shutdown wakeups are normal socket lifecycle events.
            pass

    def _validate_client(self) -> None:
        host = self.headers.get("Host", "")
        parsed = urlparse("//" + host)
        try:
            port = parsed.port
        except ValueError as error:
            raise RequestRejected("Invalid Host", 403) from error
        if (
            parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or port != self.server.server_port
        ):
            raise RequestRejected("Local Host header with the server port is required", 403)
        if self.headers.get("Origin") is not None:
            raise RequestRejected("Browser-origin requests are not allowed", 403)
        token = self.server.auth_token
        if token and not hmac.compare_digest(
            self.headers.get("Authorization", "").encode("utf-8"),
            ("Bearer " + token).encode("utf-8"),
        ):
            raise RequestRejected("Authentication required", 401)

    def _read_body(self, length: int) -> bytes:
        chunks = []
        remaining = length
        while remaining:
            timeout = self._read_deadline - time.monotonic()
            if timeout <= 0:
                raise TimeoutError("Request body deadline exceeded")
            self.connection.settimeout(timeout)
            chunk = self.rfile.read1(min(remaining, 8192))
            if not chunk:
                if self._read_expired:
                    raise TimeoutError("Request body deadline exceeded")
                raise ValueError("Incomplete JSON body")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def log_message(self, format: str, *args: Any) -> None:
        bn.log_info(format % args)

    def _send(self, data: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def _fail(self, error: Exception) -> None:
        if isinstance(error, RequestRejected):
            self._send({"error": str(error)}, error.status)
        elif isinstance(error, ServerStoppingError):
            self._send({"error": str(error)}, 503)
        elif isinstance(error, TimeoutError):
            self._send({"error": str(error)}, 408)
        elif isinstance(error, ConflictError):
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
        self.binary_ops = self.binary_ops.for_view(binary_id)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        try:
            self._validate_client()
            self._finish_read()
            if path == "/binaries":
                data = BinaryNinjaEndpoints(self.binary_ops).list_binaries()
                self._send(data)
                return
            if not path.startswith("/agent/"):
                raise LookupError("Unknown route")
            binary_id = self._required(params, "binaryId")
            with self.server.operation():
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
            self._validate_client()
            if (
                self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise RequestRejected("Content-Type must be application/json", 415)
            if self.headers.get("Transfer-Encoding") is not None:
                raise RequestRejected("Transfer-Encoding is not supported", 400)
            if urlparse(self.path).path != "/agent/annotate":
                raise LookupError("Unknown route")
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 65536:
                raise ValueError("JSON body must be 1..65536 bytes")
            data = json.loads(self._read_body(length))
            self._finish_read()
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
            binary_id = self._required(data, "binary_id")
            with self.server.operation():
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
        self.server: BoundedThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.binary_ops = BinaryOperations(config.binary_ninja)
        self._lifecycle_lock = threading.Lock()
        self.stopping = False

    def start(self) -> None:
        with self._lifecycle_lock:
            if self.server is not None or self.stopping:
                raise RuntimeError("Server is already running or stopping")
            if self.config.server.host not in ("localhost", "127.0.0.1"):
                raise ValueError("HTTP server must bind to IPv4 loopback")
            handler = type(
                "AgentRequestHandlerWithOps",
                (AgentRequestHandler,),
                {"binary_ops": self.binary_ops},
            )
            self.server = BoundedThreadingHTTPServer(
                (self.config.server.host, self.config.server.port),
                handler,
                read_timeout=self.config.server.read_timeout,
                shutdown_timeout=self.config.server.shutdown_timeout,
                auth_token=self.config.server.auth_token,
            )
            self.thread = threading.Thread(
                target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
            )
            self.thread.start()
        bn.log_info(
            f"Agent HTTP server started on {self.config.server.host}:{self.config.server.port}"
        )

    def stop_async(self) -> None:
        threading.Thread(target=self.stop, name="MCP server shutdown", daemon=True).start()

    def stop(self) -> None:
        with self._lifecycle_lock:
            if self.server is None or self.stopping:
                return
            self.stopping = True
            server = self.server
            thread = self.thread
            server.begin_shutdown()
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=1.0)
        # An SDK call already running cannot be forcibly interrupted. Keep the
        # lifecycle in Stopping until it exits to prevent overlapping restarts.
        if not server.wait_workers(0):
            threading.Thread(target=self._finish_stop, args=(server,), daemon=True).start()
        else:
            self._finish_stop(server)

    def _finish_stop(self, server: BoundedThreadingHTTPServer) -> None:
        server.wait_workers()
        with self._lifecycle_lock:
            self.thread = None
            self.server = None
            self.stopping = False
        bn.log_info("Agent HTTP server stopped")
