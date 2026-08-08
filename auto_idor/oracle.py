"""The decision oracle: does a response prove a broken access control?

The old approach ("status == 200 => vulnerable") drowns in false positives
because plenty of endpoints legitimately return 200. This oracle instead reasons
about *access* using three reference responses for the same object id:

* **owner**   -- the victim identity reading its own object (authorized truth).
* **attacker**-- another identity reading the victim's object (the test).
* **denied**  -- the anonymous baseline (what "properly refused" looks like).

An IDOR exists when the attacker's response matches the owner's *and* diverges
from the denied baseline: the attacker got data that access control should have
withheld. If the attacker's response instead matches the denied baseline, the
endpoint simply isn't protecting that object for anyone, which is not IDOR.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from typing import List, Optional

from .http import Response

# Collapse runs of whitespace so cosmetic formatting differences don't drag
# down the similarity of two otherwise identical objects.
_WS_RE = re.compile(r"\s+")


def _normalize(body: str) -> str:
    return _WS_RE.sub(" ", body).strip()


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"          # attacker obtained the victim's object
    SUSPICIOUS = "SUSPICIOUS"          # attacker got success but content diverges
    NOT_VULNERABLE = "NOT_VULNERABLE"  # properly denied, or endpoint is public
    INCONCLUSIVE = "INCONCLUSIVE"      # baseline could not be established


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


# Comparison is done on a bounded prefix; whole-body diffing is quadratic and the
# leading section is enough to tell two objects apart.
_COMPARE_CAP = 20_000


def similarity(a: str, b: str) -> float:
    """Ratio in [0, 1] of how alike two response bodies are."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    na, nb = _normalize(a), _normalize(b)
    return SequenceMatcher(None, na[:_COMPARE_CAP], nb[:_COMPARE_CAP]).ratio()


@dataclass
class Judgement:
    verdict: Verdict
    confidence: Confidence
    reason: str
    sim_to_owner: float
    sim_to_denied: float
    reflected_id: bool
    leaked_secrets: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.leaked_secrets is None:
            self.leaked_secrets = []


class Oracle:
    def __init__(self, high_threshold: float = 0.95, medium_threshold: float = 0.6):
        self.high = high_threshold
        self.medium = medium_threshold

    def evaluate(
        self,
        object_id: str,
        owner: Response,
        attacker: Response,
        denied: Optional[Response],
        victim_secrets: Optional[List[str]] = None,
    ) -> Judgement:
        # Without a working owner baseline we cannot claim the attacker saw the
        # "real" object, so refuse to guess.
        if owner is None or owner.failed or not owner.ok:
            return Judgement(
                Verdict.INCONCLUSIVE,
                Confidence.NONE,
                f"owner could not read its own object (status "
                f"{owner.status if owner else 'n/a'}); cannot baseline",
                0.0,
                0.0,
                False,
            )

        if attacker.failed:
            return Judgement(
                Verdict.NOT_VULNERABLE,
                Confidence.NONE,
                f"attacker request errored: {attacker.error}",
                0.0,
                0.0,
                False,
            )

        sim_owner = similarity(attacker.body, owner.body)
        sim_denied = similarity(attacker.body, denied.body) if denied and not denied.failed else 0.0
        reflected = bool(object_id) and object_id in attacker.body

        secrets = [s for s in (victim_secrets or []) if s]
        leaked = [s for s in secrets if s in attacker.body]
        # A leaked secret only counts if the anonymous baseline does NOT also
        # receive it -- otherwise the data is simply public, not an IDOR.
        denied_body = denied.body if denied and not denied.failed else ""
        leaked = [s for s in leaked if s not in denied_body]

        # Attacker was refused: the healthy, expected outcome.
        if not attacker.ok:
            return Judgement(
                Verdict.NOT_VULNERABLE,
                Confidence.HIGH,
                f"attacker received status {attacker.status} (access denied)",
                sim_owner,
                sim_denied,
                reflected,
            )

        # Strongest signal: the victim's private canary appeared verbatim in the
        # attacker's response and not in the anonymous baseline.
        if leaked:
            return Judgement(
                Verdict.VULNERABLE,
                Confidence.HIGH,
                f"victim's private data leaked to attacker: {', '.join(repr(s) for s in leaked)}",
                sim_owner,
                sim_denied,
                reflected,
                leaked,
            )

        # Endpoint is simply public: the anonymous baseline also gets the owner's
        # content, so nothing was bypassed.
        denied_is_public = (
            denied is not None
            and not denied.failed
            and denied.ok
            and similarity(denied.body, owner.body) >= self.high
        )
        if denied_is_public:
            return Judgement(
                Verdict.NOT_VULNERABLE,
                Confidence.HIGH,
                "anonymous baseline also receives this object; endpoint is public",
                sim_owner,
                sim_denied,
                reflected,
            )

        # Attacker's success body matches the owner's real object and differs
        # from the denied baseline: access control was bypassed.
        if sim_owner >= self.high and sim_denied < self.high:
            return Judgement(
                Verdict.VULNERABLE,
                Confidence.HIGH,
                f"attacker response matches owner's object "
                f"(similarity {sim_owner:.2f}) and differs from denied baseline",
                sim_owner,
                sim_denied,
                reflected,
            )

        if reflected and sim_owner >= self.medium:
            return Judgement(
                Verdict.VULNERABLE,
                Confidence.MEDIUM,
                f"victim's id reflected in a successful response "
                f"(similarity {sim_owner:.2f})",
                sim_owner,
                sim_denied,
                reflected,
            )

        if sim_owner >= self.medium:
            return Judgement(
                Verdict.SUSPICIOUS,
                Confidence.MEDIUM,
                f"attacker got success and partially matches owner "
                f"(similarity {sim_owner:.2f}); verify manually",
                sim_owner,
                sim_denied,
                reflected,
            )

        return Judgement(
            Verdict.SUSPICIOUS,
            Confidence.LOW,
            f"attacker got status {attacker.status} but content diverges from "
            f"owner (similarity {sim_owner:.2f}); likely a different/empty object",
            sim_owner,
            sim_denied,
            reflected,
        )
