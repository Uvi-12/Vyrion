"""RFC 8785 JSON Canonicalization Scheme (JCS) and commitments.

A single normative encoding so any language signs identical bytes. Implements the
JCS rules: keys sorted by UTF-16 code unit, no insignificant whitespace, minimal
number formatting, and JSON string escaping. Used for the signing payload and the
arguments commitment.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _fmt_number(n) -> str:
    if isinstance(n, bool):
        return "true" if n else "false"
    if isinstance(n, int):
        return str(n)
    if n != n or n in (float("inf"), float("-inf")):
        raise ValueError("non-finite numbers are not permitted in JCS")
    if n == int(n) and abs(n) < 1e15:
        return str(int(n))
    return repr(n)


def _escape(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x08:
            out.append("\\b")
        elif o == 0x09:
            out.append("\\t")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0C:
            out.append("\\f")
        elif o == 0x0D:
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canon(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _fmt_number(value)
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: [ord(c) for c in kv[0]])
        return "{" + ",".join(_escape(k) + ":" + _canon(v) for k, v in items) + "}"
    raise TypeError(f"unserializable type: {type(value)}")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a JSON-compatible value."""
    return _canon(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def arguments_commitment(args: dict) -> str:
    """A stable commitment to the actual invocation arguments."""
    return "sha256:" + sha256_hex(canonicalize(args))
