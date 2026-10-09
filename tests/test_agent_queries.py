import hashlib
import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace as Obj
from typing import Any

module_path = Path(__file__).resolve().parents[1] / "plugin" / "core" / "read_only_queries.py"
spec = importlib.util.spec_from_file_location("read_only_queries", module_path)
assert spec is not None and spec.loader is not None
queries = importlib.util.module_from_spec(spec)
spec.loader.exec_module(queries)
binary_identity = queries.binary_identity
functions_containing = queries.functions_containing
page_functions = queries.page_functions
page_instructions = queries.page_instructions
page_strings = queries.page_strings
page_symbols = queries.page_symbols
page_related_functions = queries.page_related_functions
page_xrefs = queries.page_xrefs
read_bytes = queries.read_bytes


class FakeView:
    def __init__(self):
        self.file: Any = None
        self.arch: Any = None
        self.view_type: str | None = None
        self.start: int | None = None
        self.end: int | None = None
        self.functions = [
            Obj(name=f"fn_{n}", raw_name=f"fn_{n}", start=0x1000 + n) for n in range(5)
        ]
        self._strings = [
            Obj(start=0x2000 + n, length=5, value=f"Text{n}", type="Ascii") for n in range(5)
        ]

    def get_strings(self):
        return iter(self._strings)

    def get_code_refs(self, address):
        assert address == 0x1000
        return (Obj(address=0x3000 + n, function=self.functions[n]) for n in range(3))

    def get_data_refs(self, address):
        assert address == 0x1000
        return iter([0x4000, 0x4001])

    def read(self, address, length):
        for ref in self._strings:
            if address == ref.start:
                return ref.value.encode()[:length]
            if ref.start < address < ref.start + ref.length and ref.length > 4096:
                return ref.value.encode()[address - ref.start : address - ref.start + length]
        return b"ABCD"[:length]

    def get_functions_containing(self, address):
        return self.functions[:1] if address == 0x1001 else []


class AgentQueryTests(unittest.TestCase):
    def setUp(self):
        self.view = FakeView()

    def test_function_pagination_and_filter(self):
        first = page_functions(self.view, offset=0, limit=2)
        self.assertEqual([row["name"] for row in first["functions"]], ["fn_0", "fn_1"])
        self.assertEqual(first["next_offset"], 2)
        last = page_functions(self.view, offset=4, limit=2)
        self.assertEqual(len(last["functions"]), 1)
        self.assertIsNone(last["next_offset"])
        self.assertEqual(page_functions(self.view, query="FN_3")["functions"][0]["name"], "fn_3")

    def test_string_pagination_and_filter(self):
        page = page_strings(self.view, query="text", offset=2, limit=2)
        self.assertEqual([row["value"] for row in page["strings"]], ["Text2", "Text3"])
        self.assertEqual(page["next_offset"], 4)
        self.assertEqual(page_strings(self.view, query="missing")["strings"], [])

    def test_string_search_checks_suffix_beyond_display_limit(self):
        self.view._strings = [
            Obj(start=0x2000, length=5006, value="A" * 5000 + "needle", type="Ascii")
        ]
        page = page_strings(self.view, query="NEEDLE")
        self.assertEqual(len(page["strings"]), 1)
        self.assertEqual(len(page["strings"][0]["value"]), 4096)
        self.assertTrue(page["strings"][0]["value_truncated"])

    def test_symbol_page(self):
        symbols = (Obj(name=f"sym{n}", address=0x3000 + n, type="Export") for n in range(3))
        page = page_symbols(symbols, "exports", offset=1, limit=1)
        self.assertEqual(page["exports"][0]["name"], "sym1")
        self.assertEqual(page["next_offset"], 2)

    def test_containing_and_related_functions(self):
        self.assertEqual(functions_containing(self.view, "0x1001")["functions"][0]["name"], "fn_0")
        function = self.view.functions[0]
        function.callers = self.view.functions[1:4]
        page = page_related_functions(function, "callers", offset=1, limit=1)
        self.assertEqual(page["functions"][0]["name"], "fn_2")
        self.assertEqual(page["next_offset"], 2)

    def test_xrefs_keep_code_and_data_order(self):
        page = page_xrefs(self.view, "0x1000", offset=2, limit=2)
        self.assertEqual([ref["kind"] for ref in page["references"]], ["code", "data"])
        self.assertEqual(page["next_offset"], 4)
        last = page_xrefs(self.view, "0x1000", offset=4, limit=2)
        self.assertEqual(len(last["references"]), 1)
        self.assertIsNone(last["next_offset"])

    def test_il_lines_and_bytes_are_bounded(self):
        instructions = [Obj(address=0x1000 + i, __str__=lambda: "unused") for i in range(3)]
        page = page_instructions(instructions, 0x1000, 1, 1)
        self.assertEqual(len(page["lines"]), 1)
        self.assertTrue(page["lines"][0].startswith("00001001"))
        self.assertEqual(page["next_offset"], 2)
        self.assertEqual(read_bytes(self.view, "0x1000", 3)["hex"], "414243")
        with self.assertRaises(ValueError):
            read_bytes(self.view, "0x1000", 4097)
        with self.assertRaises(ValueError):
            page_functions(self.view, limit=201)

    def test_identity_hash_is_current_file_on_disk(self):
        original = module_path
        self.view.file = Obj(filename=str(original) + ".bndb", original_filename=str(original))
        self.view.arch = Obj(name="x86_64")
        self.view.view_type = "PE"
        self.view.start = 0x1000
        self.view.end = 0x2000
        identity = binary_identity(self.view, include_sha256=True)
        self.assertEqual(identity["architecture"], "x86_64")
        self.assertEqual(
            identity["original_sha256"], hashlib.sha256(original.read_bytes()).hexdigest()
        )
        self.assertEqual(identity["hash_status"], "current_original_file")


if __name__ == "__main__":
    unittest.main()
