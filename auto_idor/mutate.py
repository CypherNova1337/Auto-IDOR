"""Identifier transformations for reaching complex / obfuscated IDORs.

Real applications rarely expose bare sequential integers. Object references are
frequently wrapped (base64, hex), URL-encoded, or padded. When the raw value is
substituted into a request it may miss the vulnerability entirely; encoding the
same logical id the way the application expects is what surfaces the bug.

Each encoding is a pure ``str -> str`` transform so it can be applied to any
identifier type (int, uuid, slug) without special-casing.
"""

from __future__ import annotations

import base64
import urllib.parse
from typing import Callable, Dict, Iterable, List

# Registry of id encodings. "raw" must exist and be the identity transform so
# the untransformed value is always tried.
ENCODINGS: Dict[str, Callable[[str], str]] = {
    "raw": lambda v: v,
    "base64": lambda v: base64.b64encode(v.encode()).decode(),
    "base64url": lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("="),
    "hex": lambda v: v.encode().hex(),
    "urlencode": lambda v: urllib.parse.quote(v, safe=""),
    "double-urlencode": lambda v: urllib.parse.quote(urllib.parse.quote(v, safe=""), safe=""),
}


def encode(value: str, encoding: str) -> str:
    """Return ``value`` transformed by the named encoding.

    Unknown encodings raise ``KeyError`` so config typos fail loudly rather
    than silently testing the wrong thing.
    """
    return ENCODINGS[encoding](str(value))


def resolve_encodings(names: Iterable[str] | None) -> List[str]:
    """Validate and de-duplicate a list of encoding names, preserving order."""
    if not names:
        return ["raw"]
    seen: List[str] = []
    for name in names:
        if name not in ENCODINGS:
            raise KeyError(
                f"unknown id encoding {name!r}; known: {', '.join(sorted(ENCODINGS))}"
            )
        if name not in seen:
            seen.append(name)
    return seen


def numeric_neighbours(seed: str, spread: int = 5) -> List[str]:
    """Sequential candidates around a numeric ``seed`` for discovery mode.

    Used only when a victim's real object ids are unknown and the tester wants
    to fuzz outward from a known-good id. Returns ``[]`` for non-numeric seeds
    (uuids, slugs) where blind incrementing is meaningless.
    """
    try:
        base = int(seed)
    except (TypeError, ValueError):
        return []
    out: List[str] = []
    for delta in range(-spread, spread + 1):
        candidate = base + delta
        if candidate >= 0 and candidate != base:
            out.append(str(candidate))
    return out
