import socket
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from agent_test_support import FakeView, HTTPFixture


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = HTTPFixture()
        self.addCleanup(self.fixture.close)
        self.view = FakeView()
        self.ops = self.fixture.mcp.binary_ops
        self.view_id = self.ops.register_view(self.view)

    def annotate(self, **changes):
        body = {
            "binary_id": self.view_id,
            "action": "set_comment",
            "address": "0x1000",
            "expected_comment": None,
            "comment": "new",
        }
        body.update(changes)
        return self.fixture.request("POST", "/agent/annotate", body)

    def test_get_is_bound_to_explicit_binary(self):
        status, data = self.fixture.request(
            "GET", f"/agent/functions?binaryId={self.view_id}&limit=2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["binary_id"], self.view_id)
        self.assertEqual(data["limit"], 2)

    def test_missing_or_closed_binary_is_an_error(self):
        status, _ = self.fixture.request("GET", "/agent/functions?binaryId=unknown")
        self.assertEqual(status, 404)

    def test_annotation_conflict_does_not_write(self):
        status, _ = self.annotate(expected_comment="stale")
        self.assertEqual(status, 409)
        self.assertFalse(self.view.comments)

    def test_annotation_success_reports_binary(self):
        status, data = self.annotate()
        self.assertEqual(status, 200)
        self.assertEqual(data["binary_id"], self.view_id)
        self.assertEqual(self.view.comments[0x1000], "new")

    def test_concurrent_annotations_only_one_wins(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(
                pool.map(lambda text: self.annotate(comment=text)[0], ["first", "second"])
            )
        self.assertEqual(sorted(statuses), [200, 409])

    def test_browser_origin_and_non_json_are_rejected(self):
        body = {
            "binary_id": self.view_id,
            "action": "set_comment",
            "address": "0x1000",
            "expected_comment": None,
            "comment": "untrusted",
        }
        status, _ = self.fixture.request(
            "POST", "/agent/annotate", body, {"Origin": "https://untrusted.example"}
        )
        self.assertEqual(status, 403)
        status, _ = self.fixture.request(
            "POST", "/agent/annotate", body, {"Content-Type": "text/plain"}
        )
        self.assertEqual(status, 415)
        status, _ = self.fixture.request("GET", "/binaries", headers={"Host": "untrusted.example"})
        self.assertEqual(status, 403)
        self.assertFalse(self.view.comments)

    def test_token_is_required_when_configured(self):
        self.fixture.http.auth_token = "test-only-token"
        status, _ = self.fixture.request("GET", "/binaries")
        self.assertEqual(status, 401)
        status, _ = self.fixture.request(
            "GET", "/binaries", headers={"Authorization": "Bearer test-only-token"}
        )
        self.assertEqual(status, 200)

    def test_incomplete_body_does_not_prevent_shutdown(self):
        client = socket.create_connection(("127.0.0.1", self.fixture.port), timeout=2)
        self.addCleanup(client.close)
        client.sendall(
            (
                f"POST /agent/annotate HTTP/1.1\r\nHost: 127.0.0.1:{self.fixture.port}\r\n"
                "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"
            ).encode()
        )
        stopped = threading.Event()

        def stop():
            self.fixture.mcp.stop()
            stopped.set()

        thread = threading.Thread(target=stop, daemon=True)
        thread.start()
        self.assertTrue(stopped.wait(1.5))
        self.assertTrue(self.fixture.http.wait_workers(1))

    def test_partial_headers_have_absolute_deadline(self):
        client = socket.create_connection(("127.0.0.1", self.fixture.port), timeout=2)
        self.addCleanup(client.close)
        client.sendall(b"GET /binaries HTTP/1.1\r\nX-Drip: ")
        deadline = time.monotonic() + 0.8
        while time.monotonic() < deadline:
            try:
                client.sendall(b"x")
            except OSError:
                break
            time.sleep(0.05)
        self.assertTrue(self.fixture.http.wait_workers(0.5))

    def test_shutdown_cancels_queued_annotation(self):
        lock = self.fixture.http._operations_lock
        lock.acquire()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.annotate)
                deadline = time.monotonic() + 1
                while not self.fixture.http._connections and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.fixture.http.begin_shutdown()
                lock.release()
                try:
                    pending.result(timeout=2)
                except (OSError, ConnectionError):
                    pass
        finally:
            if lock.locked():
                lock.release()
        self.assertFalse(self.view.comments)

    def test_registry_stays_responsive_during_a_serialized_operation(self):
        with self.fixture.http._operations_lock:
            with ThreadPoolExecutor(max_workers=1) as pool:
                rows = pool.submit(self.ops.list_open_binaries).result(timeout=0.5)
                self.assertEqual(rows[0]["id"], self.view_id)


if __name__ == "__main__":
    unittest.main()
