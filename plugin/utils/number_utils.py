import re


def _decode_escaped_string(s: str) -> bytes:
    r"""Decode a C/JSON-like escaped string into raw bytes.

    Supports: \n, \r, \t, \\ and \xNN hex escapes.
    """
    replacements = {
        r"\\n": "\n",
        r"\\r": "\r",
        r"\\t": "\t",
        r"\\\\": "\\",
        r"\"": '"',
        r"\'": "'",
    }
    for k, v in replacements.items():
        s = s.replace(k, v)

    def repl_hex(m):
        try:
            return bytes([int(m.group(1), 16)]).decode("latin1")
        except Exception:
            return m.group(0)

    s = re.sub(r"\\x([0-9a-fA-F]{2})", repl_hex, s)
    return s.encode("latin1", errors="ignore")


def _fits_unsigned(value: int, size: int) -> bool:
    if size <= 0:
        return False
    return 0 <= value < (1 << (size * 8))


def _fits_signed(value: int, size: int) -> bool:
    if size <= 0:
        return False
    minv = -(1 << (size * 8 - 1))
    maxv = (1 << (size * 8 - 1)) - 1
    return minv <= value <= maxv


def _auto_size_for_value(value: int, signed: bool) -> int:
    for size in (1, 2, 4, 8):
        if signed:
            if _fits_signed(value, size):
                return size
        else:
            if _fits_unsigned(value, size):
                return size
    return 8


def convert_number(text: str, size_param) -> dict:
    """Convert a number-like text into multiple representations.

    text: decimal ("123"), hex ("0x7b" or "7Bh"), binary ("0b1111011"), octal ("0o173"),
          char ('A'), or ASCII string ("ABC" or with escapes like "A\x42\n").
    size: desired byte size (1,2,4,8). 0/None auto-fits (numbers) or uses string length (strings).
    """
    original_text = text
    text = (text or "").strip()

    try:
        size = int(size_param) if size_param is not None else 0
    except Exception:
        size = 0

    result = {
        "input": {"text": original_text, "size": size},
        "kind": None,
        "bases": {},
        "bytes": {},
        "little_endian": {},
        "big_endian": {},
        "c_literal": None,
        "c_string": None,
        "warnings": [],
    }

    if not text:
        result["warnings"].append("empty input")
        return result

    if len(text) >= 3 and text[0] == "'" and text[-1] == "'":
        inner = text[1:-1]
        b = _decode_escaped_string(inner)
        if not b:
            val = 0
        else:
            val = b[0]
        result["kind"] = "char"
        if size <= 0:
            size = 1

        formatted = _format_numeric_value(val, size)
        b = val & 0xFF
        formatted["c_literal"] = _to_c_char(b)
        result.update(formatted)
        return result

    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        inner = text[1:-1]
        raw = _decode_escaped_string(inner)
        result["kind"] = "string"
        if size <= 0:
            size = min(len(raw), 8) if raw else 1

        le_bytes = (raw + b"\x00" * size)[:size]
        be_bytes = (b"\x00" * size + raw)[-size:]

        result["bytes"] = {
            "length": len(raw),
            "hex": raw.hex(),
        }
        result["c_string"] = _to_c_string(raw)
        result["little_endian"] = {
            "hex": le_bytes.hex(),
            "uint": int.from_bytes(le_bytes, "little", signed=False),
            "int": int.from_bytes(le_bytes, "little", signed=True),
        }
        result["big_endian"] = {
            "hex": be_bytes.hex(),
            "uint": int.from_bytes(be_bytes, "big", signed=False),
            "int": int.from_bytes(be_bytes, "big", signed=True),
        }

        u = result["little_endian"]["uint"]
        result["bases"] = {
            "dec": str(u),
            "hex": hex(u),
            "oct": oct(u),
            "bin": bin(u),
        }
        return result

    signed = False
    try:
        if text.lower().startswith("0x") or re.match(r"^[0-9a-fA-F_]+h$", text):
            if text.lower().startswith("0x"):
                val = int(text.replace("_", ""), 16)
            else:
                val = int(text[:-1].replace("_", ""), 16)
        elif text.lower().startswith("0b"):
            val = int(text.replace("_", ""), 2)
        elif text.lower().startswith("0o"):
            val = int(text.replace("_", ""), 8)
        else:
            val = int(text.replace("_", ""), 10)
            signed = val < 0
    except Exception:
        raw = text.encode("latin1", errors="ignore")
        result["kind"] = "string"
        if size <= 0:
            size = min(len(raw), 8) if raw else 1
        le_bytes = (raw + b"\x00" * size)[:size]
        be_bytes = (b"\x00" * size + raw)[-size:]
        result["bytes"] = {"length": len(raw), "hex": raw.hex()}
        result["c_string"] = _to_c_string(raw)
        result["little_endian"] = {
            "hex": le_bytes.hex(),
            "uint": int.from_bytes(le_bytes, "little", signed=False),
            "int": int.from_bytes(le_bytes, "little", signed=True),
        }
        result["big_endian"] = {
            "hex": be_bytes.hex(),
            "uint": int.from_bytes(be_bytes, "big", signed=False),
            "int": int.from_bytes(be_bytes, "big", signed=True),
        }
        u = result["little_endian"]["uint"]
        result["bases"] = {"dec": str(u), "hex": hex(u), "oct": oct(u), "bin": bin(u)}
        result["warnings"].append("Parsed as a string because numeric parsing failed")
        return result

    result["kind"] = "int"
    if size <= 0:
        size = _auto_size_for_value(val, signed)

    formatted = _format_numeric_value(val, size)
    if size == 1:
        formatted["c_literal"] = _to_c_char(val & 0xFF)
    return formatted


def _format_numeric_value(val: int, size: int) -> dict:
    mask = (1 << (size * 8)) - 1
    uval = val & mask
    le = uval.to_bytes(size, "little", signed=False)
    be = uval.to_bytes(size, "big", signed=False)

    res = {
        "kind": "int",
        "input": {"value": val, "size": size},
        "bytes": {"length": size, "hex": le.hex()},
        "little_endian": {
            "hex": le.hex(),
            "uint": int.from_bytes(le, "little", signed=False),
            "int": int.from_bytes(le, "little", signed=True),
        },
        "big_endian": {
            "hex": be.hex(),
            "uint": int.from_bytes(be, "big", signed=False),
            "int": int.from_bytes(be, "big", signed=True),
        },
        "bases": {
            "dec": str(uval),
            "hex": hex(uval),
            "oct": oct(uval),
            "bin": bin(uval),
        },
        "warnings": [],
    }
    return res


def _to_c_char(b: int) -> str:
    """Return a C character literal for a byte value."""
    escapes = {
        0x07: r"\a",
        0x08: r"\b",
        0x09: r"\t",
        0x0A: r"\n",
        0x0B: r"\v",
        0x0C: r"\f",
        0x0D: r"\r",
        0x22: r"\"",
        0x27: r"\'",
        0x5C: r"\\",
    }
    if b in escapes:
        body = escapes[b]
    elif 0x20 <= b <= 0x7E:
        body = chr(b)
    else:
        body = f"\\x{b:02x}"
    return f"'{body}'"


def _to_c_string(raw: bytes) -> str:
    r"""Return a C string literal representing the raw bytes (may be truncated by caller)."""
    out = ""
    for ch in raw:
        if ch == 0x22:
            out += r"\""
        elif ch == 0x5C:
            out += r"\\"
        elif ch == 0x0A:
            out += r"\n"
        elif ch == 0x0D:
            out += r"\r"
        elif ch == 0x09:
            out += r"\t"
        elif 0x20 <= ch <= 0x7E:
            out += chr(ch)
        else:
            out += f"\\x{ch:02x}"
    return '"' + out + '"'
