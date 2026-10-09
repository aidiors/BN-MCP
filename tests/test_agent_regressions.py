import gc
import unittest
import weakref
from types import SimpleNamespace as Obj
from typing import Any

from agent_test_support import (
    FakeView,
    HTTPFixture,
    StringReference,
    SymbolBinding,
    SymbolType,
    load_plugin_modules,
)

operations, endpoints, server, config = load_plugin_modules()


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.ops = operations.BinaryOperations(config.BinaryNinjaConfig())

    def test_dead_id_cannot_annotate_another_binary(self):
        first, second = FakeView("a.exe"), FakeView("b.exe")
        old_id = self.ops.register_view(first)
        self.ops.current_view = second
        del first
        gc.collect()
        fixture = HTTPFixture()
        self.addCleanup(fixture.close)
        fixture.mcp.binary_ops = self.ops
        fixture.http.RequestHandlerClass.binary_ops = self.ops
        status, _ = fixture.request(
            "POST",
            "/agent/annotate",
            {
                "binary_id": old_id,
                "action": "rename_function",
                "address": "0x1000",
                "expected_name": "sub_1000",
                "new_name": "wrong_binary",
            },
        )
        self.assertEqual(status, 404)
        self.assertEqual(second.functions[0].name, "sub_1000")

    def test_views_with_same_path_keep_distinct_ids(self):
        pe, raw = FakeView("same.exe", "PE"), FakeView("same.exe", "Raw")
        first, second = self.ops.register_view(pe), self.ops.register_view(raw)
        self.assertNotEqual(first, second)
        self.assertEqual(len(self.ops.list_open_binaries()), 2)
        self.ops.select_view(first)
        self.assertIs(self.ops.current_view, pe)

    def test_query_binding_survives_gui_current_view_changes(self):
        first, second = FakeView("a.exe"), FakeView("b.exe")
        view_id = self.ops.register_view(first)
        bound = self.ops.for_view(view_id)
        self.ops.current_view = second
        self.assertIs(bound.current_view, first)
        self.assertIs(self.ops.current_view, second)

    def test_gui_views_remain_available_until_their_file_is_closed(self):
        view = FakeView()
        metadata = view.file
        reference = weakref.ref(view)
        view_id = self.ops.register_view(view, keep_alive=True)
        del view
        gc.collect()
        self.assertIsNotNone(reference())
        self.assertEqual(self.ops.list_open_binaries()[0]["id"], view_id)
        self.ops.unregister_file(metadata)
        gc.collect()
        self.assertIsNone(reference())
        with self.assertRaises(LookupError):
            self.ops.for_view(view_id)

    def test_indexed_lookup_does_not_scan_functions(self):
        view: Any = FakeView()
        function = view.functions[0]
        view.get_functions_by_name = lambda name: [function] if name == "known" else []

        class ForbiddenScan:
            def __iter__(self):
                raise AssertionError("Indexed lookup should not scan all functions")

        view.functions = ForbiddenScan()
        self.ops.current_view = view
        self.assertIs(self.ops.get_function_by_name_or_address("known"), function)

    def test_missing_name_scans_once_and_request_cache_avoids_repeat(self):
        names_read = []

        class Function:
            @property
            def name(self):
                names_read.append(1)
                return "other"

        view: Any = FakeView()
        view.functions = [Function() for _ in range(10000)]
        view.get_functions_by_name = lambda _: []
        bound = self.ops.for_view(self.ops.register_view(view))
        self.assertIsNone(bound.get_function_by_name_or_address("missing"))
        self.assertIsNone(bound.get_function_by_name_or_address("missing"))
        self.assertEqual(len(names_read), 10000)

    def test_string_display_reads_are_bounded_and_queries_find_suffix(self):
        view: Any = FakeView()
        raw = b"A" * 100000 + b"needle"
        view._strings = [StringReference(view, 0x2000, raw)]
        bytes_requested = []
        read = view.read

        def counted_read(address, length):
            bytes_requested.append(length)
            return read(address, length)

        view.read = counted_read
        ranges = []
        get_strings = view.get_strings

        def ranged_strings(start, length):
            ranges.append((start, length))
            return get_strings(start, length)

        view.get_strings = ranged_strings
        self.ops.current_view = view
        row = self.ops.get_strings_page()["strings"][0]
        self.assertEqual(len(row["value"]), 4096)
        self.assertTrue(row["value_truncated"])
        self.assertLessEqual(sum(bytes_requested), 8192)
        self.assertTrue(all(length <= 65536 for _, length in ranges))
        self.assertEqual(len(self.ops.get_strings_page(query="NEEDLE")["strings"]), 1)

    def test_string_search_handles_chunk_boundaries_and_unicode_encodings(self):
        for encoding, kind, endian in [
            ("utf-8", "Utf8String", "LittleEndian"),
            ("utf-16-le", "Utf16String", "LittleEndian"),
            ("utf-16-be", "Utf16String", "BigEndian"),
            ("utf-32-le", "Utf32String", "LittleEndian"),
            ("utf-32-be", "Utf32String", "BigEndian"),
        ]:
            with self.subTest(encoding=encoding):
                view: Any = FakeView()
                view.endianness = Obj(name=endian)
                value = "A" * (4096 // len("A".encode(encoding)) - 2) + "Straße needle"
                view._strings = [StringReference(view, 0x2000, value.encode(encoding), kind)]
                self.ops.current_view = view
                rows = self.ops.get_strings_page(query="STRASSE NEEDLE")["strings"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["value"], value[:4096])

    def test_disposed_view_id_is_rejected(self):
        class DisposableView(FakeView):
            disposed = False

            @property
            def handle(self):
                if self.disposed:
                    raise ReferenceError("disposed")
                return object()

        view = DisposableView()
        view.disposed = False
        view_id = self.ops.register_view(view)
        view.disposed = True
        with self.assertRaises(LookupError):
            self.ops.for_view(view_id)

    def test_imports_and_exports_respect_symbol_categories_and_binding(self):
        view: Any = FakeView()
        kinds = [
            SymbolType.ImportedFunctionSymbol,
            SymbolType.ImportAddressSymbol,
            SymbolType.ImportedDataSymbol,
            SymbolType.ExternalSymbol,
            SymbolType.FunctionSymbol,
            SymbolType.DataSymbol,
            SymbolType.FunctionSymbol,
        ]
        bindings = [SymbolBinding.GlobalBinding] * 4 + [
            SymbolBinding.LocalBinding,
            SymbolBinding.GlobalBinding,
            SymbolBinding.WeakBinding,
        ]
        view.symbols = [
            Obj(name=f"sym{i}", address=0x1000 + i, type=kind, binding=binding)
            for i, (kind, binding) in enumerate(zip(kinds, bindings, strict=True))
        ]
        self.ops.current_view = view
        self.assertEqual(
            {row["name"] for row in self.ops.get_symbols_page("imports")["imports"]},
            {"sym0", "sym1", "sym2", "sym3"},
        )
        self.assertEqual(
            {row["name"] for row in self.ops.get_symbols_page("exports")["exports"]},
            {"sym5", "sym6"},
        )

    def test_stack_page_converts_only_requested_window(self):
        reads = []

        class Variable:
            storage = -8
            type = Obj(width=8)

            @property
            def name(self):
                reads.append(1)
                return "var"

        view: Any = FakeView()
        view.functions[0].stack_layout = [Variable() for _ in range(10000)]
        self.ops.current_view = view
        page = endpoints.BinaryNinjaEndpoints(self.ops).get_stack_frame_page("0x1000", 9998, 1)
        self.assertEqual(len(page["variables"]), 1)
        self.assertTrue(page["truncated"])
        self.assertLessEqual(len(reads), 2)
