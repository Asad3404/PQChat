"""JSON envelopes between client and relay (PROJECT-BRIEF.md §5.5, SR-9).

Every envelope is a JSON object with a ``type`` and a fixed set of fields. ``parse`` checks:
the total size, that the JSON is an object, that the type is known, that the key set is
*exactly* the expected one (no missing, no extra keys), each field's type and maximum length,
and that binary fields are canonical base64url without padding. Only then is anything used.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any

MAX_ENVELOPE = 256 * 1024
MAX_BLOB = 160 * 1024
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")


class EnvelopeError(ValueError):
    """The envelope is malformed. Never echo its content back."""


@dataclass(frozen=True)
class Field:
    kind: str  # "str", "int", "blob", "username", "bloblist"
    max_len: int = 0
    max_items: int = 0


def _blob(max_len: int) -> Field:
    return Field("blob", max_len)


# Bounds: identity 5,392 B; prekey ≤ 4,579 B; bundle ≤ 21,406 B; message ≤ 64 KiB + header.
SCHEMAS: dict[str, dict[str, Field]] = {
    # relay -> client
    "challenge": {"nonce": _blob(32)},
    "ok": {"req": Field("int")},
    "error": {"req": Field("int"), "code": Field("str", 32)},
    "bundle": {"req": Field("int"), "username": Field("username"), "bundle": _blob(32 * 1024)},
    "deliver": {
        "id": Field("int"),
        "from": Field("username"),
        "kind": Field("str", 8),
        "blob": _blob(MAX_BLOB),
    },
    "prekey_count": {"req": Field("int"), "one_time": Field("int")},
    # client -> relay
    "register": {
        "req": Field("int"),
        "username": Field("username"),
        "identity": _blob(8 * 1024),
        "sig_ed": _blob(64),
        "sig_pq": _blob(3309),
    },
    "login": {
        "req": Field("int"),
        "username": Field("username"),
        "sig_ed": _blob(64),
        "sig_pq": _blob(3309),
    },
    "upload_prekeys": {
        "req": Field("int"),
        "signed": Field("bloblist", 8 * 1024, 2),
        "one_time": Field("bloblist", 8 * 1024, 25),  # 25 x ~6 KB base64 < 256 KB
    },
    "fetch_bundle": {"req": Field("int"), "username": Field("username")},
    "send": {
        "req": Field("int"),
        "to": Field("username"),
        "kind": Field("str", 8),
        "blob": _blob(MAX_BLOB),
    },
    "ack": {"id": Field("int")},
    "count_prekeys": {"req": Field("int")},
}

MESSAGE_KINDS = {"init", "msg"}


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str, max_len: int) -> bytes:
    if not isinstance(text, str) or len(text) > (max_len * 4 + 2) // 3 + 1:
        raise EnvelopeError("blob too long")
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise EnvelopeError("blob is not base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise EnvelopeError("blob is not base64url") from None
    if b64e(data) != text:  # canonical form only: one encoding per value
        raise EnvelopeError("blob is not canonical base64url")
    if len(data) > max_len:
        raise EnvelopeError("blob too long")
    return data


def _check(name: str, spec: Field, value: Any) -> Any:
    if spec.kind == "int":
        if type(value) is not int or not 0 <= value < 2**53:
            raise EnvelopeError(f"{name} must be a non-negative integer")
        return value
    if spec.kind == "str":
        if not isinstance(value, str) or len(value) > spec.max_len:
            raise EnvelopeError(f"{name} must be a short string")
        return value
    if spec.kind == "username":
        if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
            raise EnvelopeError(f"{name} is not a valid username")
        return value
    if spec.kind == "blob":
        return b64d(value, spec.max_len)
    if spec.kind == "bloblist":
        if not isinstance(value, list) or len(value) > spec.max_items:
            raise EnvelopeError(f"{name} must be a list of at most {spec.max_items} items")
        return [b64d(v, spec.max_len) for v in value]
    raise EnvelopeError("schema error")  # pragma: no cover - programming error


def parse(raw: str | bytes, allowed: set[str]) -> tuple[str, dict[str, Any]]:
    """Validate an envelope and return (type, decoded fields)."""
    if len(raw) > MAX_ENVELOPE:
        raise EnvelopeError("envelope too large")
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise EnvelopeError("not JSON") from None
    if not isinstance(obj, dict):
        raise EnvelopeError("envelope must be an object")
    kind = obj.get("type")
    if not isinstance(kind, str) or kind not in allowed or kind not in SCHEMAS:
        raise EnvelopeError("unknown envelope type")
    schema = SCHEMAS[kind]
    if set(obj) != set(schema) | {"type"}:
        raise EnvelopeError("unexpected or missing fields")
    fields = {name: _check(name, spec, obj[name]) for name, spec in schema.items()}
    if "kind" in fields and kind in ("send", "deliver") and fields["kind"] not in MESSAGE_KINDS:
        raise EnvelopeError("unknown message kind")
    return kind, fields


def build(envelope_type: str, /, **fields: Any) -> str:
    """Encode an envelope; bytes become base64url. Validates against the schema too."""
    kind = envelope_type
    schema = SCHEMAS[kind]
    if set(fields) != set(schema):
        raise EnvelopeError("unexpected or missing fields")
    out: dict[str, Any] = {"type": kind}
    for name, value in fields.items():
        if isinstance(value, bytes | bytearray):
            out[name] = b64e(bytes(value))
        elif isinstance(value, list):
            out[name] = [b64e(bytes(v)) for v in value]
        else:
            out[name] = value
    text = json.dumps(out, separators=(",", ":"))
    parse(text, {kind})  # never send something we would reject ourselves
    return text
