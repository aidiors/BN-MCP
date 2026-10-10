"""Agent operations bound to one explicit view, with a separate shared registry."""

from __future__ import annotations

from typing import Any

import binaryninja as bn

from . import decompilation_edits
from .config import BinaryNinjaConfig
from .function_analysis import (
    analysis_status,
    calls_page,
    fit_context,
    function_summary,
    revision,
    variables_page,
)
from .legacy_operations import LegacyBinaryOperations
from .read_only_queries import (
    binary_identity,
    functions_containing,
    page_functions,
    page_instructions,
    page_items,
    page_related_functions,
    page_strings,
    page_symbols,
    page_xrefs,
    read_bytes,
)
from .symbol_queries import symbols_for
from .view_registry import ViewRegistry


class BinaryOperations(LegacyBinaryOperations):
    def __init__(self, config: BinaryNinjaConfig, registry: ViewRegistry | None = None):
        self.config = config
        self.registry = registry if registry is not None else ViewRegistry()
        self._bound_view: Any = None
        self._is_bound = False
        self._function_cache: dict[str | int, Any] = {}

    @property
    def _current_view(self):
        return self._bound_view if self._is_bound else self.registry.current

    @_current_view.setter
    def _current_view(self, view):
        if self._is_bound:
            self._bound_view = view
        else:
            self.registry.set_current(view)
        self._function_cache.clear()

    @property
    def current_view(self):
        return self._current_view

    @current_view.setter
    def current_view(self, view):
        self._current_view = view

    def for_view(self, binary_id: str) -> BinaryOperations:
        bound = BinaryOperations(self.config, self.registry)
        bound._is_bound = True
        bound._bound_view = self.registry.resolve(binary_id)
        return bound

    def register_view(self, view, *, keep_alive: bool = False) -> str:
        return self.registry.register(view, keep_alive=keep_alive)

    def _register_view(self, view) -> str:
        return self.register_view(view)

    def list_open_binaries(self):
        return self.registry.listing()

    def unregister_file(self, metadata):
        return self.registry.unregister_file(metadata)

    def unregister_by_filename(self, filename):
        return self.registry.unregister_filename(filename)

    def select_view(self, binary_id: str):
        try:
            view = self.registry.resolve(binary_id)
        except LookupError:
            return None
        self.current_view = view
        return {"id": binary_id, "filename": view.file.filename}

    def get_function_by_name_or_address(self, identifier: str | int) -> bn.Function | None:
        view = self._current_view
        if view is None:
            raise RuntimeError("No binary loaded")
        if self._is_bound and identifier in self._function_cache:
            return self._function_cache[identifier]
        function = None
        try:
            address = (
                int(identifier, 16 if identifier.lower().startswith("0x") else 10)
                if isinstance(identifier, str)
                else int(identifier)
            )
            function = view.get_function_at(address)
        except (ValueError, TypeError):
            pass
        if function is None:
            lookup = getattr(view, "get_functions_by_name", None)
            matches = lookup(str(identifier)) if callable(lookup) else []
            if len(matches) > 1:
                raise ValueError("Function name is ambiguous. Use its start address.")
            if matches:
                function = matches[0]
        if function is None:
            symbol = view.get_symbol_by_raw_name(str(identifier))
            if symbol is not None:
                function = view.get_function_at(symbol.address)
        if function is None:
            needle = str(identifier).casefold()
            exact = None
            folded = None
            ambiguous = False
            for candidate in view.functions:
                name = candidate.name
                if name == identifier:
                    if exact is not None:
                        raise ValueError("Function name is ambiguous. Use its start address.")
                    exact = candidate
                if name.casefold() == needle:
                    ambiguous = folded is not None
                    folded = candidate
            if exact is not None:
                function = exact
            elif ambiguous:
                raise ValueError("Function name is ambiguous. Use its start address.")
            else:
                function = folded
        if self._is_bound:
            self._function_cache[identifier] = function
        return function

    def get_binary_identity(self, include_sha256: bool = False) -> dict[str, Any]:
        result = binary_identity(self._current_view, include_sha256=include_sha256)
        if self._current_view is not None:
            result["view_id"] = self.register_view(self._current_view)
        return result

    def _function(self, identifier: str | int):
        function = self.get_function_by_name_or_address(identifier)
        if function is None:
            raise LookupError(f"Function not found: {identifier}")
        return function

    def get_function_info(self, identifier: str | int) -> dict[str, Any] | None:
        function = self.get_function_by_name_or_address(identifier)
        return (
            None if function is None else function_summary(function, self._edit_version(function))
        )

    def _edit_version(self, function, *, advance: bool = False):
        identifier = self.registry.register(self._current_view)
        return self.registry.edit_version(identifier, function.start, advance=advance)

    def _variable_version(self, function, variable_id: str, *, advance: bool = False):
        identifier = self.registry.register(self._current_view)
        variable_version = self.registry.edit_version(
            identifier, function.start, variable_id=variable_id, advance=advance
        )
        return revision(self._edit_version(function), variable_version)

    def get_analysis_status(self):
        return analysis_status(self._current_view)

    def get_variables_page(self, identifier: str, offset: int = 0, limit: int = 100):
        function = self._function(identifier)
        return variables_page(
            function, offset, limit, lambda var_id: self._variable_version(function, var_id)
        )

    def get_calls_page(
        self, identifier: str, direction: str = "outgoing", offset: int = 0, limit: int = 100
    ):
        return calls_page(self._current_view, self._function(identifier), direction, offset, limit)

    def get_function_context(
        self,
        identifier: str,
        include: list[str],
        line_limit: int = 80,
        item_limit: int = 20,
        max_chars: int = 32768,
    ):
        allowed = {"decompile", "calls", "variables", "callers"}
        if not include or len(include) != len(set(include)) or not set(include) <= allowed:
            raise ValueError(
                "include must select distinct decompile, calls, variables or callers sections"
            )
        if (
            not 1 <= line_limit <= 200
            or not 1 <= item_limit <= 100
            or not 2048 <= max_chars <= 65536
        ):
            raise ValueError(
                "line_limit must be 1..200, item_limit 1..100 and max_chars 2048..65536"
            )
        function = self._function(identifier)
        result = {
            "binary_id": self.registry.register(self._current_view),
            "function": function_summary(function, self._edit_version(function)),
            "sections": {},
            "unavailable": {},
        }
        for name in include:
            try:
                if name == "decompile":
                    section = self.get_function_decompiled_page(identifier, 0, line_limit)
                elif name == "calls":
                    section = self.get_calls_page(identifier, "outgoing", 0, item_limit)
                elif name == "variables":
                    section = self.get_variables_page(identifier, 0, item_limit)
                else:
                    section = self.get_related_functions_page(identifier, "callers", 0, item_limit)
                result["sections"][name] = section
            except (RuntimeError, AttributeError) as error:
                result["unavailable"][name] = str(error)[:512]
        result["analysis"] = self.get_analysis_status()
        return fit_context(result, max_chars)

    def get_type_page(self, name: str, offset: int = 0, limit: int = 100):
        return decompilation_edits.inspect_type(self._current_view, name, offset, limit)

    def edit_decompilation(self, data: dict[str, Any]):
        action = data.get("action")
        if action == "define_type":
            return decompilation_edits.define_type(self._current_view, data)
        if action not in ("edit_variable", "set_function_type"):
            raise ValueError("Unsupported decompilation edit")
        address = data.get("address")
        if not isinstance(address, str) or not address:
            raise ValueError("address must be a function start address")
        from .read_only_queries import _address

        function = self._current_view.get_function_at(_address(address))
        if function is None:
            raise LookupError("Function not found at start address")
        if action == "edit_variable":
            result = decompilation_edits.edit_variable(
                self._current_view,
                function,
                data,
                self._variable_version(function, str(data.get("variable_id"))),
            )
            self._variable_version(function, data["variable_id"], advance=True)
        else:
            result = decompilation_edits.set_function_type(
                self._current_view, function, data, self._edit_version(function)
            )
            self._edit_version(function, advance=True)
        return result

    def get_functions_page(
        self, query: str = "", offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        return page_functions(self._current_view, query, offset, limit)

    def get_strings_page(
        self,
        query: str = "",
        offset: int = 0,
        limit: int = 100,
        include_refs: bool = False,
        ref_limit: int = 5,
    ) -> dict[str, Any]:
        if not 1 <= ref_limit <= 20:
            raise ValueError("ref_limit must be 1..20")
        result = page_strings(self._current_view, query, offset, limit)
        if include_refs:
            for row in result["strings"]:
                if row["address"] is not None:
                    refs = self.get_xrefs_to_page(row["address"], 0, ref_limit)
                    row["references"] = refs["references"]
                    row["references_truncated"] = refs["truncated"]
        return result

    def get_symbols_page(self, kind: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        if self._current_view is None:
            raise RuntimeError("No binary loaded")
        symbols = symbols_for(self._current_view, kind)
        return page_symbols(symbols, kind, offset, limit)

    def get_functions_containing(self, address: str) -> dict[str, Any]:
        return functions_containing(self._current_view, address)

    def get_related_functions_page(
        self, identifier: str, relation: str, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        function = self.get_function_by_name_or_address(identifier)
        if function is None:
            raise ValueError(f"Function not found: {identifier}")
        return page_related_functions(function, relation, offset, limit)

    def read_bytes_page(self, address: str, length: int) -> dict[str, Any]:
        return read_bytes(self._current_view, address, length)

    def get_function_il_page(
        self,
        identifier: str,
        view: str = "hlil",
        ssa: bool = False,
        offset: int = 0,
        limit: int = 80,
    ) -> dict[str, Any]:
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("offset must be >= 0 and limit must be 1..200")
        if view not in ("hlil", "mlil", "llil"):
            raise ValueError("view must be hlil, mlil, or llil")
        if ssa and view == "hlil":
            raise ValueError("SSA is available only for mlil and llil")
        current_view = self._current_view
        if current_view is None:
            raise RuntimeError("No binary loaded")
        function = self.get_function_by_name_or_address(identifier)
        if function is None:
            raise ValueError(f"Function not found: {identifier}")
        if getattr(function, "analysis_skipped", False):
            function.analysis_skipped = False
            current_view.update_analysis_and_wait()
        il = getattr(function, view, None)
        if il is None:
            raise RuntimeError(f"{view} is unavailable for {identifier}")
        if ssa and view != "hlil":
            il = getattr(il, "ssa_form", None)
            if il is None:
                raise RuntimeError(f"{view} SSA is unavailable for {identifier}")
        return {
            "function": self.get_function_info(identifier),
            "view": view,
            "ssa": ssa,
            **page_instructions(il.instructions, function.start, offset, limit),
        }

    def get_function_decompiled_page(
        self, identifier: str, offset: int = 0, limit: int = 80
    ) -> dict[str, Any]:
        current_view = self._current_view
        if current_view is None:
            raise RuntimeError("No binary loaded")
        function = self.get_function_by_name_or_address(identifier)
        if function is None:
            raise ValueError(f"Function not found: {identifier}")
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("offset must be >= 0 and limit must be 1..200")
        if getattr(function, "analysis_skipped", False):
            function.analysis_skipped = False
            current_view.update_analysis_and_wait()
        hlil = getattr(function, "hlil", None)
        if hlil is None:
            raise RuntimeError(f"HLIL is unavailable for {identifier}")

        representation = None
        rendered_lines = None
        language_representation = getattr(function, "language_representation", None)
        if callable(language_representation):
            try:
                representation = language_representation("Pseudo C")
                if representation is not None:
                    rendered_lines = representation.get_linear_lines(hlil.root)
            except Exception:
                rendered_lines = None

        def convert_line(line):
            contents = getattr(line, "contents", line)
            address = getattr(contents, "address", None)
            value = str(line)
            return {
                "text": value[:4096],
                "text_truncated": len(value) > 4096,
                "address": hex(address) if address is not None else None,
                "il_index": getattr(contents, "instr_index", None),
            }

        if rendered_lines is not None:
            page = page_items(
                rendered_lines,
                offset,
                limit,
                convert_line,
                "records",
            )
            result_language = "pseudo_c"
        else:
            page = page_items(hlil.instructions, offset, limit, convert_line, "records")
            result_language = "hlil"
        for index, row in enumerate(page["records"], offset):
            row["line_index"] = index
        page["lines"] = [
            f"{int(row['address'], 16) if row['address'] is not None else function.start:08x}        {row['text']}"
            if result_language == "hlil"
            else row["text"]
            for row in page["records"]
        ]

        return {
            "function": {"name": function.name, "address": hex(function.start)},
            "representation": result_language,
            **page,
        }

    def get_function_disassembly_page(
        self, identifier: str, offset: int = 0, limit: int = 80
    ) -> dict[str, Any]:
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("offset must be >= 0 and limit must be 1..200")
        current_view = self._current_view
        if current_view is None:
            raise RuntimeError("No binary loaded")
        function = self.get_function_by_name_or_address(identifier)
        if function is None:
            raise ValueError(f"Function not found: {identifier}")
        if getattr(function, "analysis_skipped", False):
            function.analysis_skipped = False
            current_view.update_analysis_and_wait()

        def disassembly_lines():
            for block in function.basic_blocks:
                get_lines = getattr(block, "get_disassembly_text", None)
                block_lines = get_lines() if callable(get_lines) else block.disassembly_text
                for line in block_lines:
                    text = str(line)
                    address = getattr(line, "address", None)
                    if address is not None:
                        text = f"{int(address):08x}        {text}"
                    yield text

        return {
            "function": {"name": function.name, "address": hex(function.start)},
            **page_items(disassembly_lines(), offset, limit, lambda line: line, "lines"),
        }

    def get_function_basic_blocks_page(
        self, identifier: str, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("offset must be >= 0 and limit must be 1..200")
        current_view = self._current_view
        if current_view is None:
            raise RuntimeError("No binary loaded")
        function = self.get_function_by_name_or_address(identifier)
        if function is None:
            raise ValueError(f"Function not found: {identifier}")
        if getattr(function, "analysis_skipped", False):
            function.analysis_skipped = False
            current_view.update_analysis_and_wait()

        def convert_block(block: Any) -> dict[str, Any]:
            edges = []
            for edge in getattr(block, "outgoing_edges", ()):
                target = getattr(edge, "target", None)
                target_start = getattr(target, "start", None)
                edges.append(
                    {
                        "type": str(getattr(edge, "type", "unknown")),
                        "target": hex(int(target_start)) if target_start is not None else None,
                        "fall_through": bool(
                            getattr(edge, "fall_through", getattr(edge, "fallthrough", False))
                        ),
                        "back_edge": bool(
                            getattr(edge, "back_edge", getattr(edge, "backedge", False))
                        ),
                    }
                )
            start = int(block.start)
            end = int(block.end)
            return {
                "index": int(getattr(block, "index", 0)),
                "start": hex(start),
                "end": hex(end),
                "length": int(getattr(block, "length", end - start)),
                "instruction_count": int(getattr(block, "instruction_count", 0)),
                "can_exit": bool(getattr(block, "can_exit", False)),
                "has_undetermined_outgoing_edges": bool(
                    getattr(block, "has_undetermined_outgoing_edges", False)
                ),
                "outgoing_edges": edges,
            }

        return {
            "function": {"name": function.name, "address": hex(function.start)},
            **page_items(function.basic_blocks, offset, limit, convert_block, "blocks"),
        }

    def get_xrefs_to_page(
        self,
        address: str,
        offset: int = 0,
        limit: int = 100,
        include_code: bool = True,
        include_data: bool = True,
    ) -> dict[str, Any]:
        return page_xrefs(
            self._current_view,
            address,
            offset=offset,
            limit=limit,
            include_code=include_code,
            include_data=include_data,
        )
