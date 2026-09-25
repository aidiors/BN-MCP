"""Bounded, JSON-friendly queries used by the agent-facing MCP tools.

These helpers accept a BinaryView-like object so their pagination and metadata
contracts can be checked without starting Binary Ninja.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from itertools import chain
from pathlib import Path
from typing import Any


def _hex(value: Any) -> str | None:
    try:
        return hex(int(value))
    except (TypeError, ValueError):
        return None


def _address(value: int | str) -> int:
    if isinstance(value, bool):
        raise ValueError("address must be hex (0x...) or decimal")
    try:
        if isinstance(value, str):
            parsed = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        else:
            parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("address must be hex (0x...) or decimal") from exc
    if parsed < 0:
        raise ValueError("address must be non-negative")
    return parsed


def _name(value: Any) -> str | None:
    if value is None:
        return None
    return getattr(value, "name", None) or str(value)


def binary_identity(view: Any, include_sha256: bool = False) -> dict[str, Any]:
    """Describe the selected analysis view and the original file, if known.

    ``original_sha256`` hashes the current file on disk. Callers must still
    confirm that it matches the bytes analyzed in a saved BNDB.
    """
    if view is None:
        return {"loaded": False}

    metadata = getattr(view, "file", None)
    database_path = getattr(metadata, "filename", None)
    original_path = getattr(metadata, "original_filename", None)
    result: dict[str, Any] = {
        "loaded": True,
        "database_path": database_path,
        "original_path": original_path,
        "architecture": _name(getattr(view, "arch", None)),
        "view_type": getattr(view, "view_type", None),
        "view_start": _hex(getattr(view, "start", None)),
        "view_end": _hex(getattr(view, "end", None)),
        "original_sha256": None,
        "hash_status": "not_requested",
    }
    if include_sha256:
        if not original_path or not Path(original_path).is_file():
            result["hash_status"] = "original_file_unavailable"
        else:
            digest = hashlib.sha256()
            with Path(original_path).open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result["original_sha256"] = digest.hexdigest()
            result["hash_status"] = "current_original_file"
    return result


def page_instructions(
    instructions: Iterable[Any], start: int, offset: int, limit: int
) -> dict[str, Any]:
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("offset must be >= 0 and limit must be 1..200")
    lines: list[str] = []
    more = False
    last_address = start
    for index, instruction in enumerate(instructions):
        current_address = getattr(instruction, "address", None)
        if current_address is not None:
            last_address = current_address
        if index < offset:
            continue
        if len(lines) == limit:
            more = True
            break
        lines.append(f"{int(last_address):08x}        {instruction}")
    return {
        "lines": lines,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(lines) if more else None,
        "truncated": more,
    }


def _page_matches(
    items: Iterable[Any], offset: int, limit: int, query: str, convert: Any
) -> tuple[list[dict[str, Any]], bool]:
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("offset must be >= 0 and limit must be 1..200")
    matches: list[dict[str, Any]] = []
    seen = 0
    needle = query.casefold()
    for item in items:
        if not needle and seen < offset:
            seen += 1
            continue
        row = convert(item)
        if needle and needle not in str(row.get("name", row.get("value", ""))).casefold():
            continue
        if seen < offset:
            seen += 1
            continue
        if len(matches) == limit:
            return matches, True
        matches.append(row)
    return matches, False


def page_functions(view: Any, query: str = "", offset: int = 0, limit: int = 100) -> dict[str, Any]:
    if view is None:
        raise RuntimeError("No binary loaded")

    def convert(function: Any) -> dict[str, Any]:
        return {
            "name": function.name,
            "raw_name": getattr(function, "raw_name", function.name),
            "address": hex(function.start),
        }

    rows, more = _page_matches(view.functions, offset, limit, query, convert)
    return {
        "functions": rows,
        "query": query,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(rows) if more else None,
        "truncated": more,
    }


def page_strings(view: Any, query: str = "", offset: int = 0, limit: int = 100) -> dict[str, Any]:
    if view is None:
        raise RuntimeError("No binary loaded")
    try:
        strings = view.get_strings()
    except (AttributeError, TypeError):
        strings = view.strings

    def convert(ref: Any) -> dict[str, Any]:
        address = getattr(ref, "start", getattr(ref, "address", None))
        length = getattr(ref, "length", None)
        value = getattr(ref, "value", None)
        if value is None and address is not None and length is not None:
            raw = view.read(address, min(length, 4096)) or b""
            value = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        value = str(value or "")
        return {
            "address": _hex(address),
            "length": length,
            "type": str(getattr(ref, "type", "")),
            "value": value[:4096],
            "value_truncated": len(value) > 4096,
        }

    rows, more = _page_matches(strings, offset, limit, query, convert)
    return {
        "strings": rows,
        "query": query,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(rows) if more else None,
        "truncated": more,
    }


def page_symbols(
    symbols: Iterable[Any], kind: str, offset: int = 0, limit: int = 100
) -> dict[str, Any]:
    if kind not in ("imports", "exports"):
        raise ValueError("kind must be imports or exports")

    def convert(symbol: Any) -> dict[str, Any]:
        return {
            "name": str(symbol.name),
            "raw_name": str(getattr(symbol, "raw_name", symbol.name)),
            "full_name": str(getattr(symbol, "full_name", symbol.name)),
            "address": hex(symbol.address),
            "type": str(symbol.type),
        }

    rows, more = _page_matches(symbols, offset, limit, "", convert)
    return {
        kind: rows,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(rows) if more else None,
        "truncated": more,
    }


def page_related_functions(
    function: Any, relation: str, offset: int = 0, limit: int = 100
) -> dict[str, Any]:
    if relation not in ("callers", "callees"):
        raise ValueError("relation must be callers or callees")

    def convert(related: Any) -> dict[str, Any]:
        return {"name": related.name, "address": hex(related.start)}

    rows, more = _page_matches(getattr(function, relation, []), offset, limit, "", convert)
    return {
        "function": {"name": function.name, "address": hex(function.start)},
        "relation": relation,
        "functions": rows,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(rows) if more else None,
        "truncated": more,
    }


def functions_containing(view: Any, address: int | str) -> dict[str, Any]:
    if view is None:
        raise RuntimeError("No binary loaded")
    target = _address(address)
    functions = [
        {"name": function.name, "address": hex(function.start)}
        for function in view.get_functions_containing(target)
    ]
    return {"address": hex(target), "functions": functions}


def read_bytes(view: Any, address: int | str, length: int) -> dict[str, Any]:
    if view is None:
        raise RuntimeError("No binary loaded")
    if not 1 <= length <= 4096:
        raise ValueError("length must be 1..4096")
    start = _address(address)
    data = view.read(start, length)
    if not data:
        raise ValueError("address is not readable")
    return {
        "address": hex(start),
        "requested_length": length,
        "actual_length": len(data),
        "hex": data.hex(),
        "partial": len(data) < length,
    }


def _code_refs(view: Any, address: int) -> Iterable[dict[str, Any]]:
    for ref in view.get_code_refs(address):
        function = getattr(ref, "function", None)
        yield {
            "kind": "code",
            "address": _hex(getattr(ref, "address", None)),
            "function": _name(function),
            "function_start": _hex(getattr(function, "start", None)),
        }


def _data_refs(view: Any, address: int) -> Iterable[dict[str, Any]]:
    for ref_address in view.get_data_refs(address):
        yield {"kind": "data", "address": _hex(ref_address)}


def page_xrefs(
    view: Any,
    address: int | str,
    offset: int = 0,
    limit: int = 100,
    include_code: bool = True,
    include_data: bool = True,
) -> dict[str, Any]:
    """Page inbound references without materializing the full xref list."""
    if view is None:
        raise RuntimeError("No binary loaded")
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("offset must be >= 0 and limit must be 1..500")
    target = _address(address)

    sources: list[Iterable[dict[str, Any]]] = []
    if include_code:
        sources.append(_code_refs(view, target))
    if include_data:
        sources.append(_data_refs(view, target))
    page: list[dict[str, Any]] = []
    has_more = False
    for index, ref in enumerate(chain.from_iterable(sources)):
        if index < offset:
            continue
        if len(page) == limit:
            has_more = True
            break
        page.append(ref)
    next_offset = offset + len(page) if has_more else None
    return {
        "target": {"address": hex(target)},
        "references": page,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
        "truncated": has_more,
    }
