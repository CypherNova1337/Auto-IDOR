"""Configuration model and loader (YAML or JSON).

A scan is described by a small set of objects:

* :class:`Identity` -- an actor with its own auth material and the object ids it
  legitimately owns.
* :class:`Rule` -- a request template plus which ids to inject and how.
* :class:`Scan` -- the whole job: base URL, transport options, identities, rules.

YAML is supported when PyYAML is installed; otherwise JSON configs still work
with no third-party dependency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .http import RequestTemplate
from .mutate import resolve_encodings


@dataclass
class Identity:
    """An actor whose access the scan compares against others."""

    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    # Object ids this identity is *supposed* to be able to access.
    owns: List[str] = field(default_factory=list)
    # Canary strings that belong to this identity and must never appear in
    # another identity's response (e.g. private email, API key, account name).
    # The single strongest IDOR signal: if a victim's secret shows up in an
    # attacker's response, access control was bypassed regardless of similarity.
    secrets: List[str] = field(default_factory=list)
    # Marks the built-in anonymous baseline identity.
    anonymous: bool = False


@dataclass
class Rule:
    """One endpoint under test and how ids are injected into it."""

    name: str
    template: RequestTemplate
    id_token: str = "{id}"
    encodings: List[str] = field(default_factory=lambda: ["raw"])
    # Additional methods to replay the same request with (method tampering).
    method_tamper: List[str] = field(default_factory=list)
    # Rule-level ids to test in addition to each victim's `owns` (e.g. shared
    # discovery targets). Usually left empty; ownership drives the matrix.
    extra_ids: List[str] = field(default_factory=list)


@dataclass
class Scan:
    base_url: str
    identities: List[Identity]
    rules: List[Rule]
    timeout: float = 15.0
    threads: int = 8
    delay: float = 0.0
    verify_tls: bool = True
    proxy: Optional[str] = None
    allow_redirects: bool = False
    # Include an implicit no-auth identity as the "properly denied" oracle.
    include_anonymous: bool = True
    # Similarity thresholds for the oracle (see oracle.py).
    high_threshold: float = 0.95
    medium_threshold: float = 0.6

    @property
    def named_identities(self) -> List[Identity]:
        result = list(self.identities)
        if self.include_anonymous and not any(i.anonymous for i in result):
            result.append(Identity(name="anonymous", anonymous=True))
        return result


class ConfigError(ValueError):
    """Raised for malformed or incomplete scan configuration."""


def _template_from_dict(data: Dict[str, Any]) -> RequestTemplate:
    return RequestTemplate(
        method=data.get("method", "GET"),
        path=data.get("path", "/"),
        query=data.get("query", {}) or {},
        headers=data.get("headers", {}) or {},
        cookies=data.get("cookies", {}) or {},
        json_body=data.get("json"),
        form=data.get("form"),
        raw_body=data.get("body"),
    )


def _identity_from_dict(data: Dict[str, Any]) -> Identity:
    if "name" not in data:
        raise ConfigError("each identity needs a 'name'")
    owns = [str(x) for x in (data.get("owns") or [])]
    secrets = [str(x) for x in (data.get("secrets") or [])]
    return Identity(
        name=str(data["name"]),
        headers=data.get("headers", {}) or {},
        cookies=data.get("cookies", {}) or {},
        owns=owns,
        secrets=secrets,
    )


def _rule_from_dict(data: Dict[str, Any]) -> Rule:
    if "name" not in data:
        raise ConfigError("each rule needs a 'name'")
    request = data.get("request")
    if not isinstance(request, dict):
        raise ConfigError(f"rule {data['name']!r} needs a 'request' block")
    encodings = resolve_encodings(data.get("encodings"))
    return Rule(
        name=str(data["name"]),
        template=_template_from_dict(request),
        id_token=data.get("id_token", "{id}"),
        encodings=encodings,
        method_tamper=[str(m).upper() for m in (data.get("method_tamper") or [])],
        extra_ids=[str(x) for x in (data.get("extra_ids") or [])],
    )


def scan_from_dict(data: Dict[str, Any]) -> Scan:
    if "base_url" not in data:
        raise ConfigError("config needs a top-level 'base_url'")
    identities = [_identity_from_dict(i) for i in (data.get("identities") or [])]
    if len(identities) < 1:
        raise ConfigError("define at least one identity (two to detect IDOR)")
    rules = [_rule_from_dict(r) for r in (data.get("rules") or [])]
    if not rules:
        raise ConfigError("define at least one rule")

    return Scan(
        base_url=str(data["base_url"]),
        identities=identities,
        rules=rules,
        timeout=float(data.get("timeout", 15.0)),
        threads=int(data.get("threads", 8)),
        delay=float(data.get("delay", 0.0)),
        verify_tls=bool(data.get("verify_tls", True)),
        proxy=data.get("proxy"),
        allow_redirects=bool(data.get("allow_redirects", False)),
        include_anonymous=bool(data.get("include_anonymous", True)),
        high_threshold=float(data.get("high_threshold", 0.95)),
        medium_threshold=float(data.get("medium_threshold", 0.6)),
    )


def load_scan(path: str) -> Scan:
    """Load a scan config from a YAML or JSON file."""
    text = Path(path).read_text(encoding="utf-8")
    suffix = Path(path).suffix.lower()

    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ConfigError(
                "YAML config requires PyYAML (`pip install pyyaml`), "
                "or use a .json config instead."
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    if not isinstance(data, dict):
        raise ConfigError("config root must be a mapping/object")
    return scan_from_dict(data)
