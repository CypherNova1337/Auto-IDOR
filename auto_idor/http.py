"""HTTP layer: per-identity sessions and request construction.

Every identity gets its own :class:`requests.Session` so cookies set by the
server during auth stay isolated between identities. A single placeholder token
(default ``{id}``) is substituted throughout the request template — path, query,
headers, cookies and JSON/form bodies at any nesting depth — which is what lets
the engine inject an object reference wherever the application actually reads it.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    import requests
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "IDOR-Auto requires the 'requests' package. Install it with:\n"
        "    pip install -r requirements.txt"
    ) from exc


@dataclass
class Response:
    """A normalized, comparable view of an HTTP response."""

    status: int
    body: str
    length: int
    elapsed_ms: int
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        """True when the response arrived and carries a 2xx status."""
        return self.error is None and 200 <= self.status < 300

    @property
    def failed(self) -> bool:
        return self.error is not None


def _substitute(value: Any, token: str, replacement: str) -> Any:
    """Recursively replace ``token`` with ``replacement`` in a template value."""
    if isinstance(value, str):
        return value.replace(token, replacement)
    if isinstance(value, list):
        return [_substitute(v, token, replacement) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, token, replacement) for k, v in value.items()}
    return value


@dataclass
class RequestTemplate:
    """Declarative description of a request with a single ``{id}`` slot."""

    method: str = "GET"
    path: str = "/"
    query: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    json_body: Optional[Any] = None
    form: Optional[Dict[str, Any]] = None
    raw_body: Optional[str] = None

    def render(self, token: str, value: str) -> "RequestTemplate":
        """Return a copy with every ``token`` occurrence replaced by ``value``."""
        return RequestTemplate(
            method=self.method,
            path=_substitute(self.path, token, value),
            query=_substitute(copy.deepcopy(self.query), token, value),
            headers=_substitute(copy.deepcopy(self.headers), token, value),
            cookies=_substitute(copy.deepcopy(self.cookies), token, value),
            json_body=_substitute(copy.deepcopy(self.json_body), token, value),
            form=_substitute(copy.deepcopy(self.form), token, value),
            raw_body=_substitute(self.raw_body, token, value),
        )


class Client:
    """Sends rendered templates for a given identity's session."""

    # Bodies are truncated before storage/comparison. IDOR oracles care about
    # whether two responses are the same object, which the first slice captures,
    # while keeping memory bounded on large downloads.
    BODY_CAP = 200_000

    def __init__(
        self,
        base_url: str,
        timeout: float = 15.0,
        verify_tls: bool = True,
        proxy: Optional[str] = None,
        allow_redirects: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.allow_redirects = allow_redirects
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def new_session(
        self,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> requests.Session:
        session = requests.Session()
        if headers:
            session.headers.update(headers)
        if cookies:
            session.cookies.update(cookies)
        return session

    def send(self, session: requests.Session, tpl: RequestTemplate) -> Response:
        url = tpl.path if tpl.path.startswith("http") else self.base_url + tpl.path
        try:
            resp = session.request(
                method=tpl.method.upper(),
                url=url,
                params=tpl.query or None,
                headers=tpl.headers or None,
                cookies=tpl.cookies or None,
                json=tpl.json_body if tpl.json_body is not None else None,
                data=(tpl.raw_body if tpl.raw_body is not None else tpl.form) or None,
                timeout=self.timeout,
                verify=self.verify_tls,
                proxies=self.proxies,
                allow_redirects=self.allow_redirects,
            )
        except requests.RequestException as exc:
            return Response(status=0, body="", length=0, elapsed_ms=0, error=str(exc))

        text = resp.text or ""
        return Response(
            status=resp.status_code,
            body=text[: self.BODY_CAP],
            length=len(resp.content),
            elapsed_ms=int(resp.elapsed.total_seconds() * 1000),
        )
