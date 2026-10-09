"""Agent operations bound to one explicit view, with a separate shared registry."""

from __future__ import annotations

from typing import Any

import binaryninja as bn

from .config import BinaryNinjaConfig
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

    def get_functions_page(
        self, query: str = "", offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        return page_functions(self._current_view, query, offset, limit)

    def get_strings_page(
        self, query: str = "", offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        return page_strings(self._current_view, query, offset, limit)

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

        if rendered_lines is not None:
            page = page_items(
                (str(line) for line in rendered_lines),
                offset,
                limit,
                lambda line: line,
                "lines",
            )
            result_language = "pseudo_c"
        else:
            page = page_instructions(hlil.instructions, function.start, offset, limit)
            result_language = "hlil"

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
