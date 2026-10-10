"""Agent workflows, bounded context and checked decompilation edits."""

import json
import threading
import unittest
from types import SimpleNamespace as Obj

from agent_test_support import FakeType, HTTPFixture, load_plugin_modules, populated_view


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        operations, _, _, config = load_plugin_modules()
        self.view = populated_view()
        self.ops = operations.BinaryOperations(config.BinaryNinjaConfig())
        self.id = self.ops.register_view(self.view)
        self.ops = self.ops.for_view(self.id)
        self.function = self.view.functions[0]

    def test_summary_supplies_signature_and_edit_revision(self):
        result = self.ops.get_function_info("0x1000")
        self.assertEqual(result["signature"], "int32_t(int32_t value)")
        self.assertEqual(result["parameters"][0]["name"], "value")
        self.assertEqual(result["ranges"], [{"start": "0x1000", "end": "0x1002"}])
        self.assertEqual(len(result["revision"]), 64)

    def test_context_replaces_separate_reads_and_contains_code_addresses(self):
        result = self.ops.get_function_context("0x1000", ["decompile", "calls", "variables"])
        self.assertEqual(
            result["sections"]["decompile"], self.ops.get_function_decompiled_page("0x1000")
        )
        self.assertEqual(
            result["sections"]["calls"]["calls"][0]["arguments"][0]["possible_values"]["value"],
            "0x10",
        )
        self.assertEqual(result["sections"]["decompile"]["records"][0]["address"], "0x1000")
        self.assertEqual(result["unavailable"], {})

    def test_context_budget_has_correct_continuation(self):
        self.function.hlil.instructions *= 100
        result = self.ops.get_function_context("0x1000", ["decompile", "variables"], 200, 20, 2048)
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=True)), 2048)
        self.assertTrue(result["budget_truncated"])
        page = result["sections"]["decompile"]
        self.assertTrue(page["truncated"])
        self.assertEqual(page["next_offset"], len(page["records"]))

    def test_only_requested_context_sections_are_executed(self):
        self.ops.get_function_decompiled_page = lambda *_: self.fail("Unrequested IL accessed")
        result = self.ops.get_function_context("0x1000", ["variables"])
        self.assertEqual(list(result["sections"]), ["variables"])

    def test_variables_convert_only_requested_page(self):
        first = self.function.vars[0]
        self.function.vars = [first, Obj()]
        result = self.ops.get_variables_page("0x1000", limit=1)
        self.assertEqual(result["variables"][0]["id"], "1")
        self.assertTrue(result["truncated"])

    def test_string_references_are_bounded_and_include_containing_function(self):
        self.view.get_code_refs = lambda address: iter(
            [
                Obj(address=0x1001, function=self.function),
                Obj(address=0x1002, function=self.function),
            ]
        )
        result = self.ops.get_strings_page(include_refs=True, ref_limit=1)
        row = result["strings"][0]
        self.assertTrue(row["references_truncated"])
        self.assertEqual(row["references"][0]["function_start"], "0x1000")

    def test_decompile_fallback_keeps_il_addresses_and_indices(self):
        self.function.language_representation = None
        self.function.hlil.instructions[0].instr_index = 7
        result = self.ops.get_function_decompiled_page("0x1000", limit=1)
        self.assertEqual(result["representation"], "hlil")
        self.assertEqual(result["records"][0]["il_index"], 7)
        self.assertEqual(result["records"][0]["address"], "0x1000")
        self.assertTrue(result["lines"][0].startswith("00001000"))

    def test_signature_edit_revision_changes_even_before_analysis_finishes(self):
        class DeferredFunction:
            start, name, type, has_user_type = (
                0x1000,
                "deferred",
                FakeType("int32_t()", kind="FunctionTypeClass"),
                False,
            )

            def __setattr__(self, key, value):
                if key == "type":
                    self.has_user_type = True
                else:
                    object.__setattr__(self, key, value)

        self.view.functions = [DeferredFunction()]
        before = self.ops.get_function_info("0x1000")
        data = {
            "action": "set_function_type",
            "address": "0x1000",
            "expected_revision": before["revision"],
            "declaration": "int test(int x)",
        }
        self.ops.edit_decompilation(data)
        self.assertEqual(self.ops.get_function_info("0x1000")["signature"], before["signature"])
        with self.assertRaisesRegex(Exception, "signature changed"):
            self.ops.edit_decompilation(data)

    def test_calls_convert_only_page_and_preserve_unknown_targets(self):
        call = self.function.call_sites[0]
        call.mlil.dest = Obj(possible_values=Obj(type=Obj(name="UndeterminedValue")))
        self.function.call_sites = [call, Obj()]
        result = self.ops.get_calls_page("0x1000", limit=1)
        self.assertTrue(result["truncated"])
        self.assertIsNone(result["calls"][0]["target"])
        self.assertEqual(result["calls"][0]["target_values"]["kind"], "UndeterminedValue")

    def test_imported_call_target_survives_missing_sdk_possible_value(self):
        call = self.function.call_sites[0]
        call.mlil.dest = Obj(
            possible_values=Obj(type=Obj(name="ImportedAddressValue")),
            value=Obj(type=Obj(name="ImportedAddressValue"), value=0x3000),
        )
        result = self.ops.get_calls_page("0x1000")
        self.assertEqual(result["calls"][0]["target"], "0x3000")
        del call.mlil.dest.value
        result = self.ops.get_calls_page("0x1000")
        self.assertIsNone(result["calls"][0]["target"])
        self.assertEqual(
            result["calls"][0]["target_values"]["unavailable_reason"], "sdk_value_unavailable"
        )

    def test_variable_edit_targets_id_not_duplicate_name_and_supports_undo(self):
        self.function.vars[1].name = self.function.vars[0].name
        before = self.ops.get_variables_page("0x1000")["variables"][1]
        result = self.ops.edit_decompilation(
            {
                "action": "edit_variable",
                "address": "0x1000",
                "variable_id": before["id"],
                "expected_revision": before["revision"],
                "new_name": "length",
                "new_type": "uint64_t",
            }
        )
        self.assertEqual(result["requested_name"], "length")
        self.assertEqual(self.function.vars[0].name, "value")
        self.assertEqual(self.view.analysis_updates, 1)
        self.view.undo()
        self.assertEqual(self.function.vars[1].name, "value")
        self.assertEqual(str(self.function.vars[1].type), "int32_t")

    def test_variable_conflict_and_parse_failure_do_not_modify_analysis(self):
        before = self.ops.get_variables_page("0x1000")["variables"][0]
        data = {
            "action": "edit_variable",
            "address": "0x1000",
            "variable_id": before["id"],
            "expected_revision": before["revision"],
            "new_type": "bad declaration",
        }
        with self.assertRaises(ValueError):
            self.ops.edit_decompilation(data)
        self.assertEqual(len(self.view._history), 0)
        self.function.vars[0].name = "changed"
        with self.assertRaisesRegex(Exception, "Variable changed"):
            self.ops.edit_decompilation(data)
        self.assertEqual(self.view.analysis_updates, 0)

    def test_distinct_variables_can_be_edited_from_one_read(self):
        variables = self.ops.get_variables_page("0x1000")["variables"]
        for variable in variables:
            self.ops.edit_decompilation(
                {
                    "action": "edit_variable",
                    "address": "0x1000",
                    "variable_id": variable["id"],
                    "expected_revision": variable["revision"],
                    "new_name": f"renamed_{variable['id']}",
                }
            )
        self.assertEqual([v.name for v in self.function.vars], ["renamed_1", "renamed_2"])

    def test_failed_variable_verification_rolls_back_edit(self):
        before = self.ops.get_variables_page("0x1000")["variables"][0]

        def broken_edit(var, new_type, name):
            var.type = new_type
            raise RuntimeError("Native annotation failed")

        self.function.create_user_var = broken_edit
        with self.assertRaises(RuntimeError):
            self.ops.edit_decompilation(
                {
                    "action": "edit_variable",
                    "address": "0x1000",
                    "variable_id": before["id"],
                    "expected_revision": before["revision"],
                    "new_name": "renamed",
                    "new_type": "uint64_t",
                }
            )
        self.assertEqual(str(self.function.vars[0].type), "int32_t")

    def test_prototype_edit_is_checked_and_undoable(self):
        before = self.ops.get_function_info("0x1000")
        data = {
            "action": "set_function_type",
            "address": "0x1000",
            "expected_revision": before["revision"],
            "declaration": "int parse(char *buffer)",
        }
        result = self.ops.edit_decompilation(data)
        self.assertEqual(result["requested_signature"], data["declaration"])
        self.assertEqual(self.function.name, before["name"])
        with self.assertRaisesRegex(Exception, "signature changed"):
            self.ops.edit_decompilation(data)
        self.view.undo()
        self.assertEqual(str(self.function.type), before["signature"])

    def test_named_type_edit_checks_member_changes_and_rejects_extra_types(self):
        data = {
            "action": "define_type",
            "name": "Record",
            "expected_revision": None,
            "declaration": "struct Record { int length; };",
        }
        result = self.ops.edit_decompilation(data)
        self.assertEqual(self.ops.get_type_page("Record")["revision"], result["revision"])
        with self.assertRaisesRegex(Exception, "Named type changed"):
            self.ops.edit_decompilation(data)
        data["expected_revision"] = result["revision"]
        data["declaration"] += " struct Other { int x; };"
        with self.assertRaises(ValueError):
            self.ops.edit_decompilation(data)
        self.view._types["Record"] = FakeType(
            "struct Record", declaration="struct Record { char x; };"
        )
        with self.assertRaisesRegex(Exception, "Named type changed"):
            self.ops.edit_decompilation(data)

    def test_status_does_not_queue_behind_analysis_and_writes_conflict_over_http(self):
        fixture = HTTPFixture()
        self.addCleanup(fixture.close)
        identifier = fixture.mcp.binary_ops.register_view(self.view)
        acquired, release = threading.Event(), threading.Event()

        def hold():
            with fixture.http.operation():
                acquired.set()
                release.wait(2)

        thread = threading.Thread(target=hold)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(release.set)
        self.assertTrue(acquired.wait(1))
        status, result = fixture.request("GET", f"/agent/analysisStatus?binaryId={identifier}")
        self.assertEqual(status, 200)
        self.assertTrue(result["ready"])
        release.set()
        body = {
            "binary_id": identifier,
            "action": "set_function_type",
            "address": "0x1000",
            "expected_revision": "0" * 64,
            "declaration": "int test(int a)",
        }
        status, result = fixture.request("POST", "/agent/annotate", body)
        self.assertEqual(status, 409)
        self.assertIn("revision", result["current"])


if __name__ == "__main__":
    unittest.main()
