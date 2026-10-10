"""Checked, undoable edits to variables, function prototypes and named types."""

from __future__ import annotations

from typing import Any

from .function_analysis import function_revision, revision, text, variable_summary
from .read_only_queries import page_items


class EditConflict(Exception):
    def __init__(self, message: str, current: Any):
        super().__init__(message)
        self.current = current


def required_text(data: dict[str, Any], key: str, maximum: int = 4096) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{key} must be nonempty text of at most {maximum} characters")
    return value


def parse_type(view: Any, declaration: str):
    try:
        # Parsing must not import or modify other types before the edit is accepted.
        return view.parse_type_string(declaration, import_dependencies=False)[0]
    except SyntaxError as error:
        raise ValueError(f"Invalid type declaration: {error}") from error


def edit_variable(
    view: Any, function: Any, data: dict[str, Any], edit_version: int | str = 0
) -> dict[str, Any]:
    variable_id = required_text(data, "variable_id", 64)
    variable = next((var for var in function.vars if str(var.identifier) == variable_id), None)
    if variable is None:
        raise LookupError("Variable not found. Read function_variables again.")
    current = variable_summary(variable, edit_version)
    if required_text(data, "expected_revision", 64) != current["revision"]:
        raise EditConflict("Variable changed", current)
    if "new_name" not in data and "new_type" not in data:
        raise ValueError("Provide new_name or new_type")
    name = required_text(data, "new_name", 256) if "new_name" in data else variable.name
    new_type = (
        parse_type(view, required_text(data, "new_type")) if "new_type" in data else variable.type
    )
    if (
        new_type is None
        or getattr(getattr(new_type, "type_class", None), "name", "") == "FunctionTypeClass"
    ):
        raise ValueError("Variable requires a data type. Use a pointer for function types.")
    with view.undoable_transaction():
        function.create_user_var(variable, new_type, name)
        if not function.is_var_user_defined(variable):
            raise RuntimeError("Variable annotation was not accepted")
    view.update_analysis()
    return {
        "success": True,
        "action": "edit_variable",
        "address": hex(function.start),
        "previous": current,
        "variable_id": variable_id,
        "requested_name": name,
        "requested_type": text(new_type),
        "analysis_requested": True,
    }


def set_function_type(
    view: Any, function: Any, data: dict[str, Any], edit_version: int = 0
) -> dict[str, Any]:
    current = {
        "signature": text(function.type),
        "revision": function_revision(function, edit_version),
    }
    if required_text(data, "expected_revision", 64) != current["revision"]:
        raise EditConflict("Function signature changed", current)
    new_type = parse_type(view, required_text(data, "declaration", 8192))
    if getattr(getattr(new_type, "type_class", None), "name", "") != "FunctionTypeClass":
        raise ValueError("declaration must describe a function prototype")
    with view.undoable_transaction():
        function.type = new_type
        if not getattr(function, "has_user_type", True):
            raise RuntimeError("Function prototype was not accepted")
    view.update_analysis()
    return {
        "success": True,
        "action": "set_function_type",
        "address": hex(function.start),
        "previous": current,
        "requested_signature": text(new_type),
        "analysis_requested": True,
    }


def type_details(view: Any, name: str) -> tuple[Any, list[str], str | None]:
    value = view.get_type_by_name(name)
    if value is None:
        return None, [], None
    lines = [str(line) for line in value.get_lines(view, name)]
    return value, lines, revision(name, str(value), value.width, value.alignment, lines)


def inspect_type(view: Any, name: str, offset: int, limit: int) -> dict[str, Any]:
    value, lines, token = type_details(view, name)
    return {
        "name": name,
        "found": value is not None,
        "type": text(value),
        "size": getattr(value, "width", None),
        "alignment": getattr(value, "alignment", None),
        "revision": token,
        **page_items(lines, offset, limit, lambda line: line[:4096], "lines"),
    }


def define_type(view: Any, data: dict[str, Any]) -> dict[str, Any]:
    name = required_text(data, "name", 256)
    declaration = required_text(data, "declaration", 16384)
    if "expected_revision" not in data or not isinstance(
        data["expected_revision"], (str, type(None))
    ):
        raise ValueError("expected_revision must be a string or null")
    _, _, current = type_details(view, name)
    if data["expected_revision"] != current:
        raise EditConflict("Named type changed", {"name": name, "revision": current})
    try:
        parsed = view.parse_types_from_string(declaration, import_dependencies=False)
    except SyntaxError as error:
        raise ValueError(f"Invalid type declaration: {error}") from error
    if parsed.variables or parsed.functions or len(parsed.types) != 1:
        raise ValueError("Define exactly one named type without variables or functions")
    parsed_name, new_type = next(iter(parsed.types.items()))
    if str(parsed_name) != name:
        raise ValueError("The declared type name must match name")
    with view.undoable_transaction():
        view.define_user_type(parsed_name, new_type)
        value, _, token = type_details(view, name)
        if value is None or value != new_type:
            raise RuntimeError("Named type edit could not be verified")
    view.update_analysis()
    return {
        "success": True,
        "action": "define_type",
        "name": name,
        "previous_revision": current,
        "revision": token,
        "analysis_requested": True,
    }
