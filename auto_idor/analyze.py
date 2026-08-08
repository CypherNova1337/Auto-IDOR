"""Smart identifier detection and raw HTTP request parsing.

Two jobs that make the tool usable against real traffic:

* :func:`detect_identifiers` -- scan a request (path, query, JSON/form body) and
  classify every value that looks like an object reference (int, uuid, hex,
  base64, ObjectId, JWT), scoring how likely each is the thing an IDOR would
  target. This turns "where do I put {id}?" into an answered question.
* :func:`parse_raw_request` -- read a raw HTTP request (e.g. copied from Burp)
  into a :class:`RequestTemplate` + base URL, optionally auto-marking the most
  promising identifier as the ``{id}`` injection slot.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .http import RequestTemplate

# -- identifier classification --------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_OBJECTID_RE = re.compile(r"^[0-9a-f]{24}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)
_INT_RE = re.compile(r"^\d+$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]{8,}$")

# Parameter/segment names that strongly suggest an object reference.
_ID_NAME_HINT = re.compile(
    r"(?:^|[_\-])(id|ids|uid|uuid|guid|pk|ref|key|no|num|"
    r"user|account|acct|order|invoice|doc|document|file|"
    r"customer|profile|member|group|team|org|project|ticket|"
    r"transaction|payment|card|message|msg|note|record)s?(?:$|[_\-])",
    re.I,
)


def classify(value: str) -> Optional[str]:
    """Return the identifier kind for ``value``, or ``None`` if it isn't one."""
    v = value.strip()
    if not v:
        return None
    if _INT_RE.match(v):
        return "int"
    if _UUID_RE.match(v):
        return "uuid"
    if _JWT_RE.match(v):
        return "jwt"
    if _OBJECTID_RE.match(v):
        return "objectid"
    if _HEX_RE.match(v):
        return "hex"
    # Base64 must actually look encoded -- a digit, an uppercase letter, or a
    # base64 symbol. This keeps plain lowercase path words ("invoices",
    # "customer") from being mistaken for encoded object references.
    looks_encoded = any(c.isdigit() or c.isupper() or c in "+/=_-" for c in v)
    if len(v) >= 8 and looks_encoded and (_B64_RE.match(v) or _B64URL_RE.match(v)):
        return "base64"
    return None


@dataclass
class Candidate:
    location: str      # e.g. "path[3]", "query[user_id]", "json[filter.orderId]"
    name: str          # segment index or key name
    value: str
    kind: str          # from classify()
    score: float       # higher = more likely an IDOR target

    def __str__(self) -> str:
        return f"{self.location} = {self.value!r} ({self.kind}, score {self.score:.2f})"


def _score(name: str, kind: str, in_path: bool) -> float:
    score = {
        "int": 0.5,
        "uuid": 0.7,
        "objectid": 0.75,
        "hex": 0.55,
        "base64": 0.5,
        "jwt": 0.3,   # usually the auth token, not the target
    }.get(kind, 0.4)
    if _ID_NAME_HINT.search(name or ""):
        score += 0.4
    if in_path:
        score += 0.15  # ids in the path are classic IDOR real estate
    return min(score, 1.0)


def _walk_json(node: Any, prefix: str, out: List[Candidate]) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(val, (dict, list)):
                _walk_json(val, path, out)
            else:
                kind = classify(str(val))
                if kind:
                    out.append(Candidate(f"json[{path}]", str(key), str(val), kind,
                                         _score(str(key), kind, in_path=False)))
    elif isinstance(node, list):
        for i, val in enumerate(node):
            path = f"{prefix}[{i}]"
            if isinstance(val, (dict, list)):
                _walk_json(val, path, out)
            else:
                kind = classify(str(val))
                if kind:
                    out.append(Candidate(f"json[{path}]", str(i), str(val), kind,
                                         _score(prefix, kind, in_path=False)))


def detect_identifiers(tpl: RequestTemplate) -> List[Candidate]:
    """Find and rank identifier-looking values across a request template."""
    out: List[Candidate] = []

    # Path segments.
    path = tpl.path.split("?", 1)[0]
    for i, seg in enumerate(path.strip("/").split("/")):
        if not seg:
            continue
        kind = classify(seg)
        if kind:
            out.append(Candidate(f"path[{i}]", str(i), seg, kind,
                                 _score(seg, kind, in_path=True)))

    # Query params (from both structured query and any inline `?a=b`).
    query: Dict[str, Any] = dict(tpl.query or {})
    if "?" in tpl.path:
        for pair in tpl.path.split("?", 1)[1].split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                query.setdefault(k, v)
    for name, value in query.items():
        kind = classify(str(value))
        if kind:
            out.append(Candidate(f"query[{name}]", str(name), str(value), kind,
                                 _score(str(name), kind, in_path=False)))

    # Bodies.
    if tpl.json_body is not None:
        _walk_json(tpl.json_body, "", out)
    if tpl.form:
        for name, value in tpl.form.items():
            kind = classify(str(value))
            if kind:
                out.append(Candidate(f"form[{name}]", str(name), str(value), kind,
                                     _score(str(name), kind, in_path=False)))

    out.sort(key=lambda c: c.score, reverse=True)
    return out


# -- raw HTTP request parsing ---------------------------------------------

def parse_raw_request(
    text: str,
    default_scheme: str = "https",
    mark: Optional[str] = None,
    token: str = "{id}",
    auto_mark: bool = True,
) -> Tuple[str, RequestTemplate]:
    """Parse a raw HTTP request into (base_url, RequestTemplate).

    If ``mark`` is given, its first occurrence anywhere in the request is
    replaced with ``token`` so the caller controls the injection point.
    Otherwise, if the request already contains ``token`` it is preserved; if
    not, the highest-scoring detected identifier is auto-marked.
    """
    if mark:
        text = text.replace(mark, token, 1)

    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty request")

    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, raw_target = parts[0], parts[1]

    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    idx = 1
    while idx < len(lines) and lines[idx].strip():
        line = lines[idx]
        if ":" in line:
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key.lower() == "cookie":
                for pair in value.split(";"):
                    if "=" in pair:
                        ck, cv = pair.split("=", 1)
                        cookies[ck.strip()] = cv.strip()
            elif key.lower() != "content-length":  # requests sets this itself
                headers[key] = value
        idx += 1
    body = "\n".join(lines[idx + 1:]).strip() if idx + 1 <= len(lines) else ""

    # Reconstruct base_url from the Host header (absolute-URI targets also work).
    host = headers.get("Host") or headers.get("host") or ""
    if raw_target.startswith("http"):
        scheme, rest = raw_target.split("://", 1)
        host = rest.split("/", 1)[0]
        target = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        base_url = f"{scheme}://{host}"
    else:
        target = raw_target
        base_url = f"{default_scheme}://{host}" if host else ""

    json_body: Optional[Any] = None
    form: Optional[Dict[str, str]] = None
    raw_body: Optional[str] = None
    ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    if body:
        if "json" in ctype.lower():
            try:
                json_body = json.loads(body)
            except json.JSONDecodeError:
                raw_body = body
        elif "x-www-form-urlencoded" in ctype.lower():
            form = {}
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    form[k] = v
        else:
            raw_body = body

    tpl = RequestTemplate(
        method=method,
        path=target,
        headers=headers,
        cookies=cookies,
        json_body=json_body,
        form=form,
        raw_body=raw_body,
    )

    # Auto-mark if requested and no explicit token is already present.
    if auto_mark and token not in _template_text(tpl):
        candidates = detect_identifiers(tpl)
        if candidates:
            tpl = _mark_candidate(tpl, candidates[0], token)
    return base_url, tpl


def _template_text(tpl: RequestTemplate) -> str:
    return json.dumps(
        [tpl.path, tpl.query, tpl.headers, tpl.cookies, tpl.json_body, tpl.form, tpl.raw_body],
        default=str,
    )


def _replace_in(node: Any, old: str, new: str) -> Any:
    if isinstance(node, str):
        return node.replace(old, new)
    if isinstance(node, list):
        return [_replace_in(v, old, new) for v in node]
    if isinstance(node, dict):
        return {k: _replace_in(v, old, new) for k, v in node.items()}
    return node


def _mark_candidate(tpl: RequestTemplate, cand: Candidate, token: str) -> RequestTemplate:
    """Replace the chosen candidate's value with the injection token."""
    loc = cand.location
    if loc.startswith("path["):
        segs = tpl.path.split("?", 1)
        parts = segs[0].strip("/").split("/")
        i = int(cand.name)
        if 0 <= i < len(parts):
            parts[i] = token
        rebuilt = "/" + "/".join(parts)
        tpl.path = rebuilt + ("?" + segs[1] if len(segs) > 1 else "")
    elif loc.startswith("query["):
        if cand.name in (tpl.query or {}):
            tpl.query[cand.name] = token
        elif "?" in tpl.path:
            base, qs = tpl.path.split("?", 1)
            pairs = []
            for pair in qs.split("&"):
                if pair.startswith(cand.name + "="):
                    pairs.append(f"{cand.name}={token}")
                else:
                    pairs.append(pair)
            tpl.path = base + "?" + "&".join(pairs)
    elif loc.startswith("json["):
        tpl.json_body = _replace_in(tpl.json_body, cand.value, token)
    elif loc.startswith("form["):
        if tpl.form and cand.name in tpl.form:
            tpl.form[cand.name] = token
    return tpl
