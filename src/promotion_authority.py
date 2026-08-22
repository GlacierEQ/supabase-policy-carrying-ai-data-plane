"""Keyless readiness receipts for transparent technical advancement.

This module preserves the promotion-authority location as a compatibility seam,
but replaces private HMAC grants with inspectable, scope-bounded evidence receipts.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class ReadinessReceipt:
    repository: str
    source_sha: str
    capability: str
    evidence: tuple[str, ...]
    nonclaims: tuple[str, ...]
    next_action: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    def fingerprint(self) -> str:
        body = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(body).hexdigest()


def create_readiness_receipt(
    *, repository: str, source_sha: str, capability: str,
    evidence: Iterable[str], nonclaims: Iterable[str], next_action: str,
) -> ReadinessReceipt:
    if not repository or not source_sha or not capability or not next_action:
        raise ValueError("repository, source_sha, capability, and next_action are required")
    return ReadinessReceipt(
        repository=repository,
        source_sha=source_sha,
        capability=capability,
        evidence=tuple(evidence),
        nonclaims=tuple(nonclaims),
        next_action=next_action,
    )


def validate_readiness_receipt(receipt: ReadinessReceipt) -> tuple[bool, str | None]:
    if not receipt.evidence:
        return False, "EVIDENCE_REQUIRED"
    if not receipt.nonclaims:
        return False, "NONCLAIMS_REQUIRED"
    return True, None
