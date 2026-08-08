"""Human and machine readable reporting of findings."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import List, TextIO

from .engine import Finding
from .oracle import Confidence, Verdict

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


_VERDICT_STYLE = {
    Verdict.VULNERABLE: ("31;1", "VULNERABLE"),
    Verdict.SUSPICIOUS: ("33;1", "SUSPICIOUS"),
    Verdict.NOT_VULNERABLE: ("32", "not-vulnerable"),
    Verdict.INCONCLUSIVE: ("90", "inconclusive"),
}


def print_progress(msg: str, end: str = "\n") -> None:
    """Progress sink for the engine; writes to stderr so stdout stays clean."""
    sys.stderr.write(msg + end)
    sys.stderr.flush()


def _line(f: Finding) -> str:
    code, label = _VERDICT_STYLE[f.judgement.verdict]
    tag = _c(code, f"[{label}/{f.judgement.confidence.value}]")
    enc = "" if f.encoding == "raw" else f" enc={f.encoding}"
    line = (
        f"{tag} {f.rule}: {_c('1', f.attacker)} -> {f.victim}'s id={f.object_id} "
        f"[{f.method}{enc}]  "
        f"attacker={f.attacker_status} owner={f.owner_status} "
        f"anon={f.denied_status if f.denied_status is not None else '-'}\n"
        f"        {f.judgement.reason}"
    )
    if f.judgement.leaked_secrets:
        leaked = ", ".join(repr(s) for s in f.judgement.leaked_secrets)
        line += "\n        " + _c("31;1", f"leaked canary: {leaked}")
    return line


def print_report(findings: List[Finding], show_all: bool = False, out: TextIO = sys.stdout) -> None:
    vulnerable = [f for f in findings if f.judgement.verdict == Verdict.VULNERABLE]
    suspicious = [f for f in findings if f.judgement.verdict == Verdict.SUSPICIOUS]

    shown = findings if show_all else (vulnerable + suspicious)
    if shown:
        out.write("\n")
    for f in shown:
        out.write(_line(f) + "\n\n")

    total = len(findings)
    denied = sum(1 for f in findings if f.judgement.verdict == Verdict.NOT_VULNERABLE)
    inconclusive = sum(1 for f in findings if f.judgement.verdict == Verdict.INCONCLUSIVE)

    out.write("=" * 60 + "\n")
    out.write("Summary\n")
    out.write("-" * 60 + "\n")
    out.write(f"  {_c('31;1', 'VULNERABLE')}     : {len(vulnerable)}\n")
    out.write(f"  {_c('33;1', 'SUSPICIOUS')}     : {len(suspicious)}\n")
    out.write(f"  not-vulnerable : {denied}\n")
    out.write(f"  inconclusive   : {inconclusive}\n")
    out.write(f"  total tests    : {total}\n")
    out.write("=" * 60 + "\n")
    if not show_all and (denied or inconclusive):
        out.write("(re-run with --all to list not-vulnerable / inconclusive tests)\n")


def write_json(findings: List[Finding], path: str) -> None:
    payload = []
    for f in findings:
        row = asdict(f)
        # asdict flattens the nested Judgement's enums to their values already
        # for str-enums, but normalize for safety.
        j = f.judgement
        row["judgement"] = {
            "verdict": j.verdict.value,
            "confidence": j.confidence.value,
            "reason": j.reason,
            "sim_to_owner": round(j.sim_to_owner, 4),
            "sim_to_denied": round(j.sim_to_denied, 4),
            "reflected_id": j.reflected_id,
            "leaked_secrets": list(j.leaked_secrets or []),
        }
        payload.append(row)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"findings": payload}, fh, indent=2)


def has_hits(findings: List[Finding]) -> bool:
    return any(
        f.judgement.verdict in (Verdict.VULNERABLE, Verdict.SUSPICIOUS)
        for f in findings
    )
