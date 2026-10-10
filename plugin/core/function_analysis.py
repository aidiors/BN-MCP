"""Bounded function metadata, variables and call arguments for agent queries."""

from __future__ import annotations

import hashlib
import json
from itertools import islice
from typing import Any

from .read_only_queries import _hex, page_items


def revision(*values: Any) -> str:
    return hashlib.sha256(json.dumps(values, default=str).encode()).hexdigest()


def text(value: Any, limit: int = 4096) -> str | None:
    return None if value is None else str(value)[:limit]


def analysis_status(view: Any) -> dict[str, Any]:
    progress = getattr(view, "analysis_progress", None)
    state = getattr(progress, "state", None)
    name = getattr(state, "name", None)
    return {
        "state": name or "unknown",
        "ready": name == "IdleState",
        "completed": getattr(progress, "count", None),
        "total": getattr(progress, "total", None),
    }


def function_revision(function: Any, edit_version: int = 0) -> str:
    return revision(function.start, function.name, getattr(function, "type", None), edit_version)


def function_summary(function: Any, edit_version: int = 0) -> dict[str, Any]:
    function_type = getattr(function, "type", None)
    parameters = list(islice(getattr(function_type, "parameters", ()), 65))
    ranges = list(islice(getattr(function, "address_ranges", ()), 33))
    symbol = getattr(function, "symbol", None)
    convention = getattr(function, "calling_convention", None)
    return {
        "name": function.name,
        "raw_name": getattr(function, "raw_name", function.name),
        "address": hex(function.start),
        "symbol": None
        if symbol is None
        else {"type": str(symbol.type), "full_name": text(symbol.full_name)},
        "signature": text(function_type),
        "return_type": text(getattr(function, "return_type", None)),
        "calling_convention": text(getattr(convention, "name", convention)),
        "parameters": [{"name": text(p.name, 256), "type": text(p.type)} for p in parameters[:64]],
        "parameters_truncated": len(parameters) > 64,
        "ranges": [{"start": _hex(r.start), "end": _hex(r.end)} for r in ranges[:32]],
        "ranges_truncated": len(ranges) > 32,
        "total_bytes": getattr(function, "total_bytes", None),
        "is_thunk": bool(getattr(function, "is_thunk", False)),
        "analysis_skipped": bool(getattr(function, "analysis_skipped", False)),
        "revision": function_revision(function, edit_version),
    }


def variable_summary(
    variable: Any, edit_version: int | str = 0, parameter_ids: set[str] | None = None
) -> dict[str, Any]:
    var_type = getattr(variable, "type", None)
    source = getattr(variable, "source_type", None)
    identifier = str(variable.identifier)
    return {
        "id": identifier,
        "name": text(variable.name, 256),
        "type": text(var_type),
        "size": getattr(var_type, "width", None),
        "storage": str(variable.storage),
        "source": getattr(source, "name", str(source)),
        "parameter": identifier in parameter_ids
        if parameter_ids is not None
        else bool(getattr(variable, "is_parameter_variable", False)),
        "revision": revision(identifier, variable.name, var_type, edit_version),
    }


def variables_page(
    function: Any, offset: int, limit: int, version_for_variable: Any = None
) -> dict[str, Any]:
    parameters = getattr(function, "parameter_vars", None)
    parameter_ids = None if parameters is None else {str(var.identifier) for var in parameters}
    return {
        "function": {"name": function.name, "address": hex(function.start)},
        **page_items(
            function.vars,
            offset,
            limit,
            lambda var: variable_summary(
                var,
                version_for_variable(str(var.identifier)) if version_for_variable else 0,
                parameter_ids,
            ),
            "variables",
        ),
    }


def possible_values(expression: Any) -> dict[str, Any]:
    values = getattr(expression, "possible_values", None)
    if values is None:
        return {"kind": "unknown"}
    kind = getattr(getattr(values, "type", None), "name", "unknown")
    result: dict[str, Any] = {"kind": kind}
    if kind in ("ConstantValue", "ConstantPointerValue", "ImportedAddressValue"):
        value = getattr(values, "value", None)
        if value is None:
            # SDK 5.1 omits the value on imported-address PossibleValueSet objects.
            # RegisterValue preserves it. Only use a fallback with the same kind.
            register_value = getattr(expression, "value", None)
            if getattr(getattr(register_value, "type", None), "name", None) == kind:
                value = getattr(register_value, "value", None)
        result["value"] = _hex(value)
        if value is None:
            result["unavailable_reason"] = "sdk_value_unavailable"
    elif kind in ("InSetOfValues", "NotInSetOfValues"):
        # Bound conversion even if the SDK supplies a large set.
        window = list(islice(values.values, 17))
        result.update(values=[_hex(v) for v in window[:16]], truncated=len(window) > 16)
    elif kind in ("SignedRangeValue", "UnsignedRangeValue"):
        window = list(islice(values.ranges, 17))
        result.update(
            ranges=[
                {"start": str(r.start), "end": str(r.end), "step": str(r.step)} for r in window[:16]
            ],
            truncated=len(window) > 16,
        )
    return result


def calls_page(view: Any, function: Any, direction: str, offset: int, limit: int) -> dict[str, Any]:
    if direction not in ("outgoing", "incoming"):
        raise ValueError("direction must be outgoing or incoming")
    sites = function.call_sites if direction == "outgoing" else function.caller_sites

    def convert(site: Any) -> dict[str, Any]:
        instruction = getattr(site, "mlil", None)
        operation = getattr(getattr(instruction, "operation", None), "name", "")
        # A mapping can point to a non-call expression. Never infer arguments from it.
        is_call = operation in ("MLIL_CALL", "MLIL_TAILCALL", "MLIL_CALL_SSA", "MLIL_TAILCALL_SSA")
        destination = getattr(instruction, "dest", None) if is_call else None
        target_values = possible_values(destination)
        target = target_values.get("value")
        symbol = view.get_symbol_at(int(target, 16)) if target else None
        arguments = list(islice(getattr(instruction, "params", ()), 33)) if is_call else []
        return {
            "address": _hex(site.address),
            "caller": {"name": site.function.name, "address": _hex(site.function.start)},
            "il_index": getattr(instruction, "instr_index", None),
            "il": "mlil",
            "text": text(instruction),
            "target": target,
            "target_name": text(symbol.name, 256) if symbol else None,
            "target_values": target_values,
            "arguments": [
                {"index": i, "expression": text(arg, 1024), "possible_values": possible_values(arg)}
                for i, arg in enumerate(arguments[:32])
            ],
            "arguments_truncated": len(arguments) > 32,
            "unavailable_reason": None if is_call else "call_il_unavailable",
        }

    return {
        "function": {"name": function.name, "address": hex(function.start)},
        "direction": direction,
        **page_items(sites, offset, limit, convert, "calls"),
    }


def fit_context(result: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """Keep a combined context within its serialized character budget."""
    if not 2048 <= max_chars <= 65536:
        raise ValueError("max_chars must be 2048..65536")
    result["budget_truncated"] = False

    def length(value):
        return len(json.dumps(value, ensure_ascii=True))

    total = length(result)
    sizes = {name: length(section) for name, section in result["sections"].items()}
    while total > max_chars:
        # Remove the largest section's last record and retain a continuation offset.
        choices = []
        for name, section in result["sections"].items():
            for key in ("records", "calls", "variables", "functions"):
                if section.get(key):
                    choices.append((sizes[name], name, key))
        if not choices:
            raise ValueError("max_chars is too small for function metadata. Increase the budget.")
        _, name, key = max(choices)
        section = result["sections"][name]
        old_metadata = length(
            {"truncated": section["truncated"], "next_offset": section["next_offset"]}
        )
        removed = section[key].pop()
        removed_size = length(removed) + (2 if section[key] else 0)
        if key == "records":
            line = section["lines"].pop()
            removed_size += length(line) + (2 if section["lines"] else 0)
        section["truncated"] = True
        section["next_offset"] = section["offset"] + len(section[key])
        new_metadata = length(
            {"truncated": section["truncated"], "next_offset": section["next_offset"]}
        )
        delta = new_metadata - old_metadata - removed_size
        sizes[name] += delta
        total += delta - int(not result["budget_truncated"])
        result["budget_truncated"] = True
    return result
