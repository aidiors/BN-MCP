import os
from typing import Any

import binaryninja as bn

from ..core.binary_operations import BinaryOperations
from ..core.read_only_queries import page_items


class BinaryNinjaEndpoints:
    def __init__(self, binary_ops: BinaryOperations):
        self.binary_ops = binary_ops

    def get_status(self) -> dict[str, Any]:
        """Get the current status of the binary view"""
        return {
            "loaded": self.binary_ops.current_view is not None,
            "filename": self.binary_ops.current_view.file.filename
            if self.binary_ops.current_view
            else None,
        }

    def get_entry_points(self) -> list[dict[str, Any]]:
        """Get entry point(s) for the current binary"""
        return self.binary_ops.get_entry_points()

    def _format_binary_listing(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """List stable view IDs with paths and view types."""
        formatted: list[dict[str, Any]] = []
        for item in raw:
            filename = item.get("filename")
            view_id = str(item.get("id") or "")
            basename = os.path.basename(filename) if filename else None
            entry: dict[str, Any] = {
                "id": view_id,
                "view_id": view_id,
                "filename": filename,
                "basename": basename,
                "active": bool(item.get("active")),
                "view_type": item.get("view_type"),
            }
            entry["selectors"] = [view_id] if view_id else []
            formatted.append(entry)
        return formatted

    def list_binaries(self) -> dict[str, Any]:
        """List concrete managed views with stable IDs and the UI active flag."""
        raw = self.binary_ops.list_open_binaries()
        return {"binaries": self._format_binary_listing(raw)}

    def select_binary(self, ident: str) -> dict[str, Any]:
        """Select an active view by its stable view_id."""
        info = self.binary_ops.select_view(ident)
        if not info:
            return {
                "error": f"Binary not found: {ident}",
                "available": self.list_binaries().get("binaries", []),
            }
        filename = info.get("filename")
        view_id = info.get("id")
        formatted = self._format_binary_listing(self.binary_ops.list_open_binaries())
        selected_entry: dict[str, Any] | None = None
        for entry in formatted:
            if view_id and entry.get("view_id") == view_id:
                selected_entry = entry
                break
        if not selected_entry:
            basename = os.path.basename(filename) if filename else None
            selectors: list[str] = []
            for candidate in (view_id, filename, basename):
                if candidate and candidate not in selectors:
                    selectors.append(candidate)
            selected_entry = {
                "id": None,
                "view_id": view_id,
                "filename": filename,
                "basename": basename,
                "active": True,
                "selectors": selectors,
            }
        else:
            selected_entry["active"] = True
        return {"status": "ok", "selected": selected_entry}

    def get_function_info(self, identifier: str) -> dict[str, Any] | None:
        """Get detailed information about a function"""
        try:
            return self.binary_ops.get_function_info(identifier)
        except Exception as e:
            bn.log_error(f"Error getting function info: {e}")
            return None

    def get_callers(self, identifiers: list[str]) -> dict[str, Any]:
        """Proxy BinaryOperations.get_callers for endpoint reuse."""
        return self.binary_ops.get_callers(identifiers)

    def get_callees(self, identifiers: list[str]) -> dict[str, Any]:
        """Proxy BinaryOperations.get_callees for endpoint reuse."""
        return self.binary_ops.get_callees(identifiers)

    def get_imports(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        return self.binary_ops.get_symbols_page("imports", offset, limit)["imports"]

    def get_exports(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        return self.binary_ops.get_symbols_page("exports", offset, limit)["exports"]

    def get_namespaces(self, offset: int = 0, limit: int = 100) -> list[str]:
        """Get list of C++ namespaces"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        namespaces = set()
        for sym in self.binary_ops.current_view.get_symbols():
            if "::" in sym.name:
                parts = sym.name.split("::")
                if len(parts) > 1:
                    namespace = "::".join(parts[:-1])
                    namespaces.add(namespace)

        sorted_namespaces = sorted(list(namespaces))
        return sorted_namespaces[offset : offset + limit]

    def get_defined_data(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Get list of defined data variables"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        data_items = []
        for var in self.binary_ops.current_view.data_vars:
            data_type = self.binary_ops.current_view.get_type_at(var)
            value = None

            try:
                if data_type and data_type.width <= 8:
                    value = str(self.binary_ops.current_view.read_int(var, data_type.width))
                else:
                    value = "(complex data)"
            except (ValueError, TypeError):
                value = "(unreadable)"

            sym = self.binary_ops.current_view.get_symbol_at(var)
            data_items.append(
                {
                    "address": hex(var),
                    "name": sym.name if sym else "(unnamed)",
                    "raw_name": sym.raw_name if sym and hasattr(sym, "raw_name") else None,
                    "value": value,
                    "type": str(data_type) if data_type else None,
                }
            )

        return data_items[offset : offset + limit]

    def search_functions(
        self, search_term: str, offset: int = 0, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Search functions by name"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        if not search_term:
            return []

        matches: list[dict[str, Any]] = []
        for func in self.binary_ops.current_view.functions:
            if search_term.lower() in func.name.lower():
                matches.append(
                    {
                        "name": func.name,
                        "address": hex(func.start),
                        "raw_name": func.raw_name if hasattr(func, "raw_name") else func.name,
                        "symbol": {
                            "type": str(func.symbol.type) if func.symbol else None,
                            "full_name": func.symbol.full_name if func.symbol else None,
                        }
                        if func.symbol
                        else None,
                    }
                )

        matches.sort(key=lambda x: x["name"])
        return matches[offset : offset + limit]

    def decompile_function(self, identifier: str) -> str | None:
        """Decompile a function by name or address"""
        try:
            return self.binary_ops.decompile_function(identifier)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {e}")
            return None

    def get_assembly_function(self, identifier: str) -> str | None:
        """Get the assembly representation of a function by name or address"""
        try:
            return self.binary_ops.get_assembly_function(identifier)
        except Exception as e:
            bn.log_error(f"Error getting assembly for function: {e}")
            return None

    def make_function_at(
        self, address: str | int, architecture: str | None = None
    ) -> dict[str, Any]:
        """Create a function at an address (no-op if already exists).

        On invalid/unknown platform (non-default arch parameter), returns an error object with
        an exhaustive list of available platforms so clients/LLMs can choose properly.
        """
        try:
            return self.binary_ops.make_function_at(address, architecture)
        except ValueError as e:
            platforms: list[str] = []
            try:
                plats_obj = getattr(bn, "Platform", None)
                if plats_obj is not None:
                    try:
                        platforms = [str(getattr(p, "name", str(p))) for p in list(plats_obj)]
                    except Exception:
                        platforms = []
            except Exception:
                platforms = []
            if not platforms:
                platforms = [
                    "decree-x86",
                    "efi-x86",
                    "efi-windows-x86",
                    "efi-x86_64",
                    "efi-windows-x86_64",
                    "efi-aarch64",
                    "efi-windows-aarch64",
                    "efi-armv7",
                    "efi-thumb2",
                    "freebsd-x86",
                    "freebsd-x86_64",
                    "freebsd-aarch64",
                    "freebsd-armv7",
                    "freebsd-thumb2",
                    "ios-aarch64",
                    "ios-armv7",
                    "ios-thumb2",
                    "ios-kernel-aarch64",
                    "ios-kernel-armv7",
                    "ios-kernel-thumb2",
                    "linux-ppc32",
                    "linux-ppcvle32",
                    "linux-ppc64",
                    "linux-ppc32_le",
                    "linux-ppc64_le",
                    "linux-rv32gc",
                    "linux-rv64gc",
                    "linux-x86",
                    "linux-x86_64",
                    "linux-x32",
                    "linux-aarch64",
                    "linux-armv7",
                    "linux-thumb2",
                    "linux-armv7eb",
                    "linux-thumb2eb",
                    "linux-mipsel",
                    "linux-mips",
                    "linux-mips3",
                    "linux-mipsel3",
                    "linux-mips64",
                    "linux-cnmips64",
                    "linux-mipsel64",
                    "mac-x86",
                    "mac-x86_64",
                    "mac-aarch64",
                    "mac-armv7",
                    "mac-thumb2",
                    "mac-kernel-x86",
                    "mac-kernel-x86_64",
                    "mac-kernel-aarch64",
                    "mac-kernel-armv7",
                    "mac-kernel-thumb2",
                    "windows-x86",
                    "windows-x86_64",
                    "windows-aarch64",
                    "windows-armv7",
                    "windows-thumb2",
                    "windows-kernel-x86",
                    "windows-kernel-x86_64",
                    "windows-kernel-windows-aarch64",
                ]
            return {"error": str(e), "available_platforms": platforms}

    def define_types(self, c_code: str) -> dict[str, str]:
        """Define types from C code string

        Args:
            c_code: C code string containing type definitions

        Returns:
            Dictionary mapping type names to their string representations

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If parsing the types fails
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        try:
            parse_result = self.binary_ops.current_view.parse_types_from_string(c_code)

            defined_types = {}
            for name, type_obj in parse_result.types.items():
                self.binary_ops.current_view.define_user_type(name, type_obj)
                defined_types[str(name)] = str(type_obj)

            return defined_types
        except Exception as e:
            raise ValueError(f"Failed to define types: {e!s}")

    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> dict[str, str]:
        """Rename a variable inside a function

        Args:
            function_name: Name of the function containing the variable
            old_name: Current name of the variable
            new_name: New name for the variable

        Returns:
            Dictionary with status message

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or variable cannot be renamed
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        function = self.binary_ops.get_function_by_name_or_address(function_name)
        if not function:
            raise ValueError(f"Function '{function_name}' not found")

        try:
            variable = function.get_variable_by_name(old_name)
            if not variable:
                raise ValueError(f"Variable '{old_name}' not found in function '{function_name}'")

            variable.name = new_name
            return {
                "status": f"Successfully renamed variable '{old_name}' to '{new_name}' in function '{function_name}'"
            }
        except Exception as e:
            raise ValueError(f"Failed to rename variable: {e!s}")

    def rename_variables(
        self,
        function_identifier: str | int,
        renames: list[dict[str, str]] | dict[str, str],
    ) -> dict[str, Any]:
        """Rename multiple local variables in a function.

        Args:
            function_identifier: Function name or address
            renames: Either a list of {"old": str, "new": str} pairs or a dict mapping old->new

        Returns:
            Dictionary with overall status and per-item results.

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or inputs are invalid
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        func = self.binary_ops.get_function_by_name_or_address(function_identifier)
        if not func:
            raise ValueError(f"Function '{function_identifier}' not found")

        pairs: list[dict[str, str]] = []
        if isinstance(renames, dict):
            for k, v in renames.items():
                if k is None or v is None:
                    continue
                pairs.append({"old": str(k), "new": str(v)})
        elif isinstance(renames, list):
            for entry in renames:
                try:
                    old = (
                        entry.get("old")
                        or entry.get("from")
                        or entry.get("src")
                        or entry.get("before")
                    )
                    new = (
                        entry.get("new")
                        or entry.get("to")
                        or entry.get("dst")
                        or entry.get("after")
                    )
                except Exception:
                    old = None
                    new = None
                if old is None or new is None:
                    continue
                pairs.append({"old": str(old), "new": str(new)})
        else:
            raise ValueError(
                "Invalid 'renames' format. Expected a list of {old,new} or an old->new mapping."
            )

        if not pairs:
            raise ValueError("No valid rename pairs provided")

        results: list[dict[str, Any]] = []
        success_count = 0

        for idx, item in enumerate(pairs, start=1):
            old_name = item.get("old")
            new_name = item.get("new")
            if not old_name or not new_name:
                results.append(
                    {
                        "index": idx,
                        "old": old_name,
                        "new": new_name,
                        "success": False,
                        "error": "Missing old or new name",
                    }
                )
                continue

            try:
                var = None
                try:
                    if hasattr(func, "get_variable_by_name"):
                        var = func.get_variable_by_name(old_name)
                except Exception:
                    var = None
                if not var:
                    results.append(
                        {
                            "index": idx,
                            "old": old_name,
                            "new": new_name,
                            "success": False,
                            "error": f"Variable '{old_name}' not found",
                        }
                    )
                    continue

                try:
                    var.name = new_name
                except Exception:
                    try:
                        if hasattr(func, "create_user_var") and hasattr(var, "storage"):
                            vtype = getattr(var, "type", None)
                            if vtype is None:
                                vtype = getattr(bn, "Type", None)
                            func.create_user_var(var, vtype, new_name)
                        else:
                            raise
                    except Exception as e:
                        results.append(
                            {
                                "index": idx,
                                "old": old_name,
                                "new": new_name,
                                "success": False,
                                "error": f"Failed to rename: {e}",
                            }
                        )
                        continue

                success_count += 1
                results.append(
                    {
                        "index": idx,
                        "old": old_name,
                        "new": new_name,
                        "success": True,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "index": idx,
                        "old": old_name,
                        "new": new_name,
                        "success": False,
                        "error": str(e),
                    }
                )

        try:
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
        except Exception:
            pass

        return {
            "status": "ok",
            "function": func.name,
            "address": hex(func.start),
            "total": len(pairs),
            "renamed": success_count,
            "results": results,
        }

    def retype_variable(self, function_name: str, name: str, type_str: str) -> dict[str, str]:
        """Retype a variable inside a function

        Args:
            function_name: Name of the function containing the variable
            name: Current name of the variable
            type: C type for the variable

        Returns:
            Dictionary with status message

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or variable cannot be retyped
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        function = self.binary_ops.get_function_by_name_or_address(function_name)
        if not function:
            raise ValueError(f"Function '{function_name}' not found")

        try:
            variable = function.get_variable_by_name(name)
            if not variable:
                raise ValueError(f"Variable '{name}' not found in function '{function_name}'")

            variable.type = type_str
            return {
                "status": f"Successfully retyped variable '{name}' to '{type_str}' in function '{function_name}'"
            }
        except Exception as e:
            raise ValueError(f"Failed to rename variable: {e!s}")

    def set_function_prototype(self, function_address: str | int, prototype: str) -> dict[str, str]:
        """Set a function's prototype by address.

        Args:
            function_address: Function address (hex string like 0x401000 or integer)
            prototype: C-style function prototype/type string (e.g., "int __cdecl f(int a)", or "int(int)" )

        Returns:
            Dictionary with status message.

        Raises:
            RuntimeError: If no binary is loaded.
            ValueError: If the function or prototype is invalid.
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        func = self.binary_ops.get_function_by_name_or_address(function_address)
        if not func:
            raise ValueError(f"Function not found for identifier '{function_address}'")

        proto = (prototype or "").strip()
        if proto.endswith(";"):
            proto = proto[:-1].strip()

        t = None
        last_error = None
        try:
            t, _ = self.binary_ops.current_view.parse_type_string(proto)
        except Exception as e:
            last_error = e
            t = None

        if t is None:
            try:
                pr = self.binary_ops.current_view.parse_types_from_string(proto)
                if pr and getattr(pr, "types", None):
                    chosen = None
                    if func.name in pr.types:
                        chosen = pr.types[func.name]
                    else:
                        for name, tobj in pr.types.items():
                            try:
                                function_type = getattr(
                                    getattr(bn.enums, "TypeClass", None),
                                    "FunctionTypeClass",
                                    None,
                                )
                                if (
                                    hasattr(tobj, "type_class")
                                    and function_type is not None
                                    and int(function_type) == int(getattr(tobj, "type_class"))
                                ):
                                    chosen = tobj
                                    break
                            except Exception:
                                chosen = tobj
                                break
                    if chosen is not None:
                        t = chosen
            except Exception as e:
                last_error = e

        if t is None:
            import re as _re

            m = _re.match(r"^\s*([^()]+?)\s*\((.*)\)\s*$", proto)
            if m and func and func.name and func.name not in proto:
                ret = m.group(1).strip()
                args = m.group(2).strip()
                candidate = f"{ret} {func.name}({args})"
                try:
                    t, _ = self.binary_ops.current_view.parse_type_string(candidate)
                except Exception as e:
                    last_error = e

        if t is None:
            raise ValueError(f"Failed to parse prototype: {proto} ({last_error})")

        try:
            func.type = t
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
        except Exception as e:
            raise ValueError(f"Failed applying type: {e!s}")

        return {
            "status": "ok",
            "function": func.name,
            "address": hex(func.start),
            "applied_type": str(t),
        }

    def declare_c_type(self, c_declaration: str) -> dict[str, Any]:
        """Create or update a local type from a single C declaration.

        Accepts any C type declaration (struct/union/enum/typedef/function type) and defines
        the resulting named types in the current BinaryView's user types. If multiple types
        are declared, all are applied.

        Args:
            c_declaration: C declaration string (e.g., "typedef struct { int a; } Foo;")

        Returns:
            Dictionary with keys:
              - defined_types: map of type name -> declaration string
              - count: number of types defined/updated

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If parsing fails or no types are found
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        decl = (c_declaration or "").strip()
        if not decl:
            raise ValueError("Empty C declaration")

        try:
            result = self.binary_ops.current_view.parse_types_from_string(decl)
        except Exception as e:
            raise ValueError(f"Failed to parse declaration: {e!s}")

        if not result or not getattr(result, "types", {}):
            raise ValueError("No named types found in declaration")

        defined: dict[str, str] = {}
        for name, type_obj in result.types.items():
            try:
                self.binary_ops.current_view.define_user_type(name, type_obj)
                defined[str(name)] = str(type_obj)
            except Exception as e:
                raise ValueError(f"Failed to define type '{name}': {e!s}")

        return {"defined_types": defined, "count": len(defined)}

    def set_local_variable_type(
        self, function_address: str | int, variable_name: str, new_type: str
    ) -> dict[str, str]:
        """Set a local variable's type in a function.

        Args:
            function_address: Function identifier (address in hex or int, or name)
            variable_name: Local variable name to retype
            new_type: C type string (e.g., "int *", "const char*", "struct Foo*")

        Returns:
            Dictionary with status message.

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If function/variable/type are invalid
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        func = self.binary_ops.get_function_by_name_or_address(function_address)
        if not func:
            raise ValueError(f"Function '{function_address}' not found")

        if not variable_name:
            raise ValueError("Missing variable name")

        var = None
        try:
            if hasattr(func, "get_variable_by_name"):
                var = func.get_variable_by_name(variable_name)
        except Exception:
            var = None

        if not var:
            raise ValueError(f"Variable '{variable_name}' not found in function '{func.name}'")

        try:
            t, _ = self.binary_ops.current_view.parse_type_string((new_type or "").strip())
        except Exception:
            t = None
        if t is None:
            try:
                var.type = new_type
                applied = str(new_type)
            except Exception:
                raise ValueError(f"Failed to parse type: '{new_type}'")
        else:
            applied = str(t)
            try:
                var.type = t
            except Exception:
                try:
                    if hasattr(func, "create_user_var") and hasattr(var, "storage"):
                        func.create_user_var(var, t, variable_name)
                    else:
                        raise ValueError("Retyping not supported by this Binary Ninja API version")
                except Exception as e:
                    raise ValueError(f"Failed to set variable type: {e!s}")

        try:
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
        except Exception:
            pass

        return {
            "status": "ok",
            "function": func.name,
            "address": hex(func.start),
            "variable": variable_name,
            "applied_type": applied,
        }

    @staticmethod
    def _stack_variable(var: Any) -> dict[str, str]:
        storage = getattr(var, "storage", 0)
        variable_type = getattr(var, "type", None)
        width = getattr(variable_type, "width", getattr(var, "width", 0))
        return {
            "name": str(getattr(var, "name", "")),
            "offset": f"{storage:#x}" if isinstance(storage, int) else str(storage),
            "size": f"{width:#x}" if isinstance(width, int) else str(width),
            "type": str(variable_type) if variable_type is not None else "",
        }

    def get_stack_frame_vars(self, function_identifier: str | int) -> list[dict[str, Any]]:
        function = self.binary_ops.get_function_by_name_or_address(function_identifier)
        if function is None:
            raise LookupError("Function not found")
        layout = getattr(function, "stack_layout", None)
        if layout is None:
            raise RuntimeError("Function has no stack information available")
        return [
            {"addr": hex(function.start), "vars": [self._stack_variable(var) for var in layout]}
        ]

    def get_stack_frame_page(
        self, function_identifier: str | int, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        function = self.binary_ops.get_function_by_name_or_address(function_identifier)
        if function is None:
            raise LookupError("Function not found")
        layout = getattr(function, "stack_layout", None)
        if layout is None:
            raise RuntimeError("Function has no stack information available")
        return {
            "function": {"name": function.name, "address": hex(function.start)},
            **page_items(layout, offset, limit, self._stack_variable, "variables"),
        }

    def patch_bytes(
        self, address: str | int, data: str | bytes | list[int], save_to_file: bool = True
    ) -> dict[str, Any]:
        """Patch bytes at a given address in the binary.

        Args:
            address: Address to patch (hex string like "0x401000" or integer)
            data: Bytes to write. Can be:
                - Hex string: "90 90" or "9090" or "0x90 0x90"
                - List of integers: [0x90, 0x90]
                - Bytes object: b"\x90\x90"
            save_to_file: If True (default), save the patched binary to disk and re-sign on macOS.
                If False, only modify the BinaryView in memory without affecting the original file.

        Returns:
            Dictionary with status, address, original bytes, and patched bytes

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If address or data format is invalid
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        try:
            return self.binary_ops.patch_bytes(address, data, save_to_file)
        except Exception as e:
            bn.log_error(f"Error patching bytes: {e}")
            raise ValueError(f"Failed to patch bytes: {e!s}")
