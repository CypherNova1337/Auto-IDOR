"""Command-line interface for IDOR-Auto.

Three subcommands:

* ``run``   -- execute a full scan from a YAML/JSON config (complex IDORs).
* ``quick`` -- ad-hoc two-identity differential test straight from flags.
* ``init``  -- write a commented example config to start from.
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

from . import __version__
from .analyze import detect_identifiers, parse_raw_request
from .config import ConfigError, Identity, Rule, Scan, load_scan
from .engine import Engine
from .http import RequestTemplate
from .mutate import resolve_encodings
from .report import has_hits, print_progress, print_report, write_json

EXAMPLE_CONFIG = """\
# IDOR-Auto scan config. Detection is differential: each identity's own reads
# and the anonymous baseline are the oracles, so a finding means one identity
# actually obtained another's object -- not merely that a URL returned 200.

base_url: https://api.example.com

# Transport (all optional)
threads: 8
timeout: 15
delay: 0.0            # seconds between requests per worker (throttle)
verify_tls: true
# proxy: http://127.0.0.1:8080   # route through Burp/mitmproxy
include_anonymous: true          # add a no-auth "properly denied" baseline

identities:
  - name: alice
    headers:
      Authorization: "Bearer ALICE_TOKEN"
    owns: [1001, 1002]           # object ids alice legitimately owns
    # Canary strings unique to alice. If any show up in bob's response for one
    # of alice's objects, that's a confirmed leak (highest confidence).
    secrets: ["alice@corp.example", "Alice Anderson"]
  - name: bob
    headers:
      Authorization: "Bearer BOB_TOKEN"
    cookies:
      session: bobs-cookie
    owns: [2001, 2002]
    secrets: ["bob@corp.example"]

rules:
  # Classic path-based reference.
  - name: get-invoice
    request:
      method: GET
      path: /api/v1/invoices/{id}

  # Complex: id lives in a nested JSON body and is base64-wrapped by the app.
  - name: order-detail
    request:
      method: POST
      path: /api/v1/orders/detail
      headers:
        Content-Type: application/json
      json:
        filter:
          orderId: "{id}"
    encodings: [raw, base64]
    method_tamper: [GET]          # also replay as GET (method-based bypass)
"""


def _parse_headers(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or []:
        if ":" not in item:
            raise SystemExit(f"invalid header {item!r}; expected 'Name: value'")
        key, _, value = item.partition(":")
        out[key.strip()] = value.strip()
    return out


def _parse_cookies(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"invalid cookie {item!r}; expected 'name=value'")
        key, _, value = item.partition("=")
        out[key.strip()] = value.strip()
    return out


def _csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def _run_scan(scan: Scan, args: argparse.Namespace) -> int:
    progress = None if args.quiet else print_progress
    engine = Engine(scan, progress=progress)
    findings = engine.run()
    print_report(findings, show_all=args.all)
    if args.output:
        write_json(findings, args.output)
        if not args.quiet:
            print_progress(f"[*] JSON written to {args.output}")
    # Exit non-zero when something needs a human's eyes (useful in CI pipelines).
    return 2 if has_hits(findings) else 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        scan = load_scan(args.config)
    except (ConfigError, OSError) as exc:
        raise SystemExit(f"config error: {exc}")
    _apply_transport_overrides(scan, args)
    return _run_scan(scan, args)


def _strip_auth(tpl: RequestTemplate) -> RequestTemplate:
    """Remove baked-in auth so each identity supplies its own credentials."""
    tpl.headers = {k: v for k, v in tpl.headers.items() if k.lower() != "authorization"}
    tpl.cookies = {}
    return tpl


def _cmd_quick(args: argparse.Namespace) -> int:
    if not args.url and not args.request:
        raise SystemExit("quick mode needs either -u/--url or -r/--request")
    if not args.owns_a and not args.owns_b:
        raise SystemExit("quick mode needs --owns-a and/or --owns-b (the ids to test)")

    base_url = ""
    if args.request:
        raw = _read_source(args.request)
        base_url, template = parse_raw_request(raw, mark=args.mark)
        template = _strip_auth(template)
        template.method = args.method.upper() if args.method != "GET" else template.method
    else:
        template = RequestTemplate(method=args.method.upper(), path=args.url)

    headers_a = _parse_headers(args.header_a)
    headers_b = _parse_headers(args.header_b)
    if args.token_a:
        headers_a.setdefault("Authorization", f"Bearer {args.token_a}")
    if args.token_b:
        headers_b.setdefault("Authorization", f"Bearer {args.token_b}")

    identities = [
        Identity(
            name="user-a",
            headers=headers_a,
            cookies=_parse_cookies(args.cookie_a),
            owns=_csv(args.owns_a),
            secrets=_csv(args.secret_a),
        ),
        Identity(
            name="user-b",
            headers=headers_b,
            cookies=_parse_cookies(args.cookie_b),
            owns=_csv(args.owns_b),
            secrets=_csv(args.secret_b),
        ),
    ]
    rule = Rule(
        name="quick",
        template=template,
        encodings=resolve_encodings(_csv(args.encodings) or None),
        method_tamper=[m.upper() for m in _csv(args.method_tamper)],
    )
    scan = Scan(base_url=base_url, identities=identities, rules=[rule])
    _apply_transport_overrides(scan, args)
    return _run_scan(scan, args)


def _read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _cmd_detect(args: argparse.Namespace) -> int:
    raw = _read_source(args.request)
    base_url, template = parse_raw_request(raw, auto_mark=False)
    candidates = detect_identifiers(template)
    print(f"[*] {template.method} {base_url}{template.path.split('?', 1)[0]}")
    if not candidates:
        print("    no identifier-looking values found")
        return 0
    print(f"[*] {len(candidates)} identifier candidate(s), best first:\n")
    for c in candidates:
        print(f"    {c}")
    print(f"\n[*] auto-mark would target: {candidates[0].location}")
    print("    use it directly:  auto-idor quick -r <file> --owns-a <ids> ...")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    from pathlib import Path

    path = Path(args.path)
    if path.exists() and not args.force:
        raise SystemExit(f"{path} already exists (use --force to overwrite)")
    path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    print(f"[*] wrote example config to {path}")
    print("    edit the identities/tokens, then: auto-idor run -c " + str(path))
    return 0


def _apply_transport_overrides(scan: Scan, args: argparse.Namespace) -> None:
    if getattr(args, "threads", None) is not None:
        scan.threads = args.threads
    if getattr(args, "delay", None) is not None:
        scan.delay = args.delay
    if getattr(args, "timeout", None) is not None:
        scan.timeout = args.timeout
    if getattr(args, "proxy", None):
        scan.proxy = args.proxy
    if getattr(args, "insecure", False):
        scan.verify_tls = False
    if getattr(args, "follow_redirects", False):
        scan.allow_redirects = True
    if getattr(args, "no_anonymous", False):
        scan.include_anonymous = False


def _add_transport_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--threads", type=int, default=None, help="concurrent workers (default 8)")
    p.add_argument("--delay", type=float, default=None, help="seconds between requests per worker")
    p.add_argument("--timeout", type=float, default=None, help="per-request timeout seconds")
    p.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--follow-redirects", action="store_true", help="follow redirects")
    p.add_argument("--no-anonymous", action="store_true", help="omit the anonymous baseline")
    p.add_argument("-o", "--output", help="write findings as JSON to this path")
    p.add_argument("--all", action="store_true", help="also print not-vulnerable/inconclusive tests")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-idor",
        description="Differential IDOR / BOLA access-control tester.",
    )
    parser.add_argument("--version", action="version", version=f"IDOR-Auto {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run a full scan from a config file")
    p_run.add_argument("-c", "--config", required=True, help="YAML or JSON scan config")
    _add_transport_flags(p_run)
    p_run.set_defaults(func=_cmd_run)

    p_quick = sub.add_parser("quick", help="ad-hoc two-identity differential test")
    p_quick.add_argument("-u", "--url", help="target URL containing {id}")
    p_quick.add_argument("-r", "--request", help="raw HTTP request file (e.g. from Burp); '-' for stdin")
    p_quick.add_argument("--mark", help="value in the raw request to replace with the {id} slot")
    p_quick.add_argument("-m", "--method", default="GET", help="HTTP method (default GET)")
    p_quick.add_argument("--token-a", help="bearer token for user-a")
    p_quick.add_argument("--token-b", help="bearer token for user-b")
    p_quick.add_argument("-H", "--header-a", action="append", default=[], help="header for user-a 'K: V' (repeatable)")
    p_quick.add_argument("--header-b", action="append", default=[], help="header for user-b 'K: V' (repeatable)")
    p_quick.add_argument("--cookie-a", action="append", default=[], help="cookie for user-a 'k=v' (repeatable)")
    p_quick.add_argument("--cookie-b", action="append", default=[], help="cookie for user-b 'k=v' (repeatable)")
    p_quick.add_argument("--owns-a", help="comma-separated ids owned by user-a")
    p_quick.add_argument("--owns-b", help="comma-separated ids owned by user-b")
    p_quick.add_argument("--secret-a", help="comma-separated canary strings private to user-a")
    p_quick.add_argument("--secret-b", help="comma-separated canary strings private to user-b")
    p_quick.add_argument("--encodings", help="comma list of id encodings (raw,base64,hex,urlencode,...)")
    p_quick.add_argument("--method-tamper", help="comma list of extra methods to replay")
    _add_transport_flags(p_quick)
    p_quick.set_defaults(func=_cmd_quick)

    p_detect = sub.add_parser("detect", help="find injectable id candidates in a raw request")
    p_detect.add_argument("-r", "--request", required=True, help="raw HTTP request file; '-' for stdin")
    p_detect.set_defaults(func=_cmd_detect)

    p_init = sub.add_parser("init", help="write an example config to start from")
    p_init.add_argument("path", nargs="?", default="idor.yaml", help="output path (default idor.yaml)")
    p_init.add_argument("--force", action="store_true", help="overwrite if it exists")
    p_init.set_defaults(func=_cmd_init)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
