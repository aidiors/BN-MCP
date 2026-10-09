"""Bounded, JSON-friendly queries used by the agent-facing MCP tools.

These helpers accept a BinaryView-like object so their pagination and metadata
contracts can be checked without starting Binary Ninja.
"""

from __future__ import annotations

import codecs
import hashlib
from collections.abc import Iterable
from itertools import chain, islice
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


def page_items(
    items: Iterable[Any], offset: int, limit: int, convert: Any, key: str
) -> dict[str, Any]:
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("offset must be >= 0 and limit must be 1..200")
    window = list(islice(items, offset, offset + limit + 1))
    more = len(window) > limit
    return {
        key: [convert(item) for item in window[:limit]],
        "offset": offset,
        "limit": limit,
        "next_offset": offset + limit if more else None,
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
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("offset must be >= 0 and limit must be 1..200")
    rows = []
    seen = 0
    more = False
    for ref in _string_references(view):
        if not query and seen < offset:
            seen += 1
            continue
        value, truncated, matches = _string_value(view, ref, query)
        if not matches:
            continue
        if seen < offset:
            seen += 1
            continue
        if len(rows) == limit:
            more = True
            break
        rows.append(
            {
                "address": _hex(getattr(ref, "start", getattr(ref, "address", None))),
                "length": getattr(ref, "length", None),
                "type": str(getattr(ref, "type", "")),
                "value": value,
                "value_truncated": truncated,
            }
        )
    return {
        "strings": rows,
        "query": query,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(rows) if more else None,
        "truncated": more,
    }


def _string_references(view: Any) -> Iterable[Any]:
    """Fetch SDK references in bounded address windows instead of one full list."""
    getter = getattr(view, "get_strings", None)
    if not callable(getter):
        yield from view.strings
        return
    start, end = getattr(view, "start", None), getattr(view, "end", None)
    if start is None or end is None:
        yield from getter()
        return
    spans = sorted(
        (int(segment.start), int(segment.end))
        for segment in getattr(view, "segments", ())
        if segment.end > segment.start
    )
    if not spans:
        spans = [(int(start), int(end))]
    previous_end = int(start)
    for span_start, span_end in spans:
        cursor = max(span_start, previous_end)
        while cursor < span_end:
            length = min(65536, span_end - cursor)
            refs = getter(cursor, length)
            for ref in refs:
                # SDK range queries may also return an overlapping earlier string.
                if cursor <= ref.start < cursor + length:
                    yield ref
            cursor += length
        previous_end = max(previous_end, span_end)


def _string_value(view: Any, ref: Any, query: str) -> tuple[str, bool, bool]:
    """Bound display reads, but search the entire decoded value incrementally."""
    needle = query.casefold()
    address = getattr(ref, "start", getattr(ref, "address", None))
    length = getattr(ref, "length", None)
    reader = getattr(view, "read", None)
    # Lightweight non-SDK adapters may expose only an already-decoded value.
    if address is None or length is None or not callable(reader):
        value = getattr(ref, "value", None)
        if value is not None:
            value = str(value)
            return value[:4096], len(value) > 4096, needle in value.casefold()
    if address is None or length is None or not callable(reader):
        raise ValueError("String reference has neither a decoded value nor readable storage")
    address, length = int(address), int(length)
    type_name = getattr(getattr(ref, "type", None), "name", str(getattr(ref, "type", ""))).lower()
    big_endian = "big" in str(getattr(getattr(view, "endianness", None), "name", "")).lower()
    codec = "utf-8"
    if "utf16" in type_name:
        codec = "utf-16-be" if big_endian else "utf-16-le"
    elif "utf32" in type_name:
        codec = "utf-32-be" if big_endian else "utf-32-le"
    elif "ascii" in type_name:
        codec = "ascii"
    decoder = None
    prefix = ""
    tail = ""
    matched = not needle
    consumed = 0
    while consumed < int(length or 0):
        raw = reader(address + consumed, min(4096, length - consumed)) or b""
        if not raw:
            break
        if decoder is None:
            if "utf16" in type_name and raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                codec = "utf-16"
            elif "utf32" in type_name and raw.startswith(
                (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")
            ):
                codec = "utf-32"
            decoder = codecs.getincrementaldecoder(codec)(errors="replace")
        consumed += len(raw)
        text = decoder.decode(raw, final=consumed >= length)
        prefix += text[: max(0, 4097 - len(prefix))]
        if not matched:
            search = tail + text.casefold()
            matched = needle in search
            tail = search[-(len(needle) - 1) :] if len(needle) > 1 else ""
        if len(prefix) > 4096 and matched:
            break
    return prefix[:4096], len(prefix) > 4096, matched


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
