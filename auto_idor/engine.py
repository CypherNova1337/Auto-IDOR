"""Scan orchestration: build the attacker/victim matrix and judge each cell.

For every rule, every victim identity's owned object ids are read back by the
victim (owner baseline) and by the anonymous baseline once, then every *other*
identity attempts to read them. Each attempt is judged by the oracle. Baseline
responses are cached so they are fetched once per (rule, id, encoding, method)
regardless of how many attackers probe them.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .config import Identity, Rule, Scan
from .http import Client, RequestTemplate, Response
from .mutate import encode
from .oracle import Confidence, Judgement, Oracle, Verdict


@dataclass
class Finding:
    rule: str
    attacker: str
    victim: str
    object_id: str
    encoding: str
    method: str
    attacker_status: int
    owner_status: int
    denied_status: Optional[int]
    judgement: Judgement

    @property
    def is_hit(self) -> bool:
        return self.judgement.verdict in (Verdict.VULNERABLE, Verdict.SUSPICIOUS)


# A unit of work: one object owned by one victim, injected one way.
@dataclass(frozen=True)
class _Target:
    rule_idx: int
    victim_idx: int
    object_id: str
    encoding: str
    method: str


class Engine:
    def __init__(self, scan: Scan, progress: Optional[Callable[[str], None]] = None):
        self.scan = scan
        self.oracle = Oracle(scan.high_threshold, scan.medium_threshold)
        self.client = Client(
            base_url=scan.base_url,
            timeout=scan.timeout,
            verify_tls=scan.verify_tls,
            proxy=scan.proxy,
            allow_redirects=scan.allow_redirects,
        )
        self.identities = scan.named_identities
        self._anon = next((i for i in self.identities if i.anonymous), None)
        self._sessions: Dict[str, "object"] = {
            ident.name: self.client.new_session(ident.headers, ident.cookies)
            for ident in self.identities
        }
        self._baseline_cache: Dict[Tuple[int, str, str, str, str], Response] = {}
        self._baseline_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._progress = progress or (lambda *_a, **_k: None)

    # -- request helpers ----------------------------------------------------
    def _rendered(self, rule: Rule, object_id: str, encoding: str, method: str) -> RequestTemplate:
        tpl = rule.template.render(rule.id_token, encode(object_id, encoding))
        if method != tpl.method.upper():
            tpl = RequestTemplate(
                method=method,
                path=tpl.path,
                query=tpl.query,
                headers=tpl.headers,
                cookies=tpl.cookies,
                json_body=tpl.json_body,
                form=tpl.form,
                raw_body=tpl.raw_body,
            )
        return tpl

    def _send_as(self, identity: Identity, rule: Rule, object_id: str, encoding: str, method: str) -> Response:
        if self.scan.delay:
            with self._rate_lock:
                time.sleep(self.scan.delay)
        tpl = self._rendered(rule, object_id, encoding, method)
        return self.client.send(self._sessions[identity.name], tpl)

    def _baseline(
        self, identity: Identity, rule_idx: int, rule: Rule,
        object_id: str, encoding: str, method: str,
    ) -> Response:
        """Fetch-and-cache a baseline response (owner or anonymous)."""
        key = (rule_idx, identity.name, object_id, encoding, method)
        with self._baseline_lock:
            cached = self._baseline_cache.get(key)
        if cached is not None:
            return cached
        resp = self._send_as(identity, rule, object_id, encoding, method)
        with self._baseline_lock:
            self._baseline_cache[key] = resp
        return resp

    # -- planning -----------------------------------------------------------
    def _targets(self) -> List[_Target]:
        targets: List[_Target] = []
        victims = [i for i in self.identities if not i.anonymous]
        for r_idx, rule in enumerate(self.scan.rules):
            methods = [rule.template.method.upper(), *rule.method_tamper]
            methods = list(dict.fromkeys(methods))  # de-dup, keep order
            for v_idx, victim in enumerate(self.identities):
                if victim.anonymous:
                    continue
                ids = list(victim.owns) + list(rule.extra_ids)
                for object_id in ids:
                    for encoding in rule.encodings:
                        for method in methods:
                            targets.append(_Target(r_idx, v_idx, object_id, encoding, method))
        if not any(v.owns for v in victims) and not any(r.extra_ids for r in self.scan.rules):
            self._progress(
                "[!] No object ids defined (identity 'owns' / rule 'extra_ids'); "
                "nothing to test."
            )
        return targets

    def _evaluate_target(self, target: _Target) -> List[Finding]:
        rule = self.scan.rules[target.rule_idx]
        victim = self.identities[target.victim_idx]

        owner_resp = self._baseline(
            victim, target.rule_idx, rule, target.object_id, target.encoding, target.method
        )
        denied_resp = (
            self._baseline(
                self._anon, target.rule_idx, rule, target.object_id, target.encoding, target.method
            )
            if self._anon
            else None
        )

        findings: List[Finding] = []
        for attacker in self.identities:
            if attacker.name == victim.name or attacker.anonymous:
                continue
            attacker_resp = self._send_as(
                attacker, rule, target.object_id, target.encoding, target.method
            )
            judgement = self.oracle.evaluate(
                target.object_id, owner_resp, attacker_resp, denied_resp,
                victim_secrets=victim.secrets,
            )
            findings.append(
                Finding(
                    rule=rule.name,
                    attacker=attacker.name,
                    victim=victim.name,
                    object_id=target.object_id,
                    encoding=target.encoding,
                    method=target.method,
                    attacker_status=attacker_resp.status,
                    owner_status=owner_resp.status,
                    denied_status=denied_resp.status if denied_resp else None,
                    judgement=judgement,
                )
            )
        return findings

    # -- public API ---------------------------------------------------------
    def run(self) -> List[Finding]:
        targets = self._targets()
        total = len(targets)
        self._progress(f"[*] {total} object/injection targets across "
                       f"{len(self.scan.rules)} rule(s), "
                       f"{len([i for i in self.identities if not i.anonymous])} identities")
        findings: List[Finding] = []
        done = 0
        with ThreadPoolExecutor(max_workers=max(1, self.scan.threads)) as pool:
            futures = {pool.submit(self._evaluate_target, t): t for t in targets}
            for future in as_completed(futures):
                findings.extend(future.result())
                done += 1
                if total:
                    self._progress(f"\r[*] progress {done}/{total} targets", end="")
        self._progress("")  # newline after progress line
        # Deterministic order: worst verdict first, then by rule/victim/id.
        severity = {
            (Verdict.VULNERABLE, Confidence.HIGH): 0,
            (Verdict.VULNERABLE, Confidence.MEDIUM): 1,
            (Verdict.VULNERABLE, Confidence.LOW): 2,
            (Verdict.SUSPICIOUS, Confidence.MEDIUM): 3,
            (Verdict.SUSPICIOUS, Confidence.LOW): 4,
        }
        findings.sort(
            key=lambda f: (
                severity.get((f.judgement.verdict, f.judgement.confidence), 9),
                f.rule, f.victim, f.object_id, f.attacker,
            )
        )
        return findings
