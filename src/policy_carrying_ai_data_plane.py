"""Policy-Carrying AI Data Plane — independent reference implementation.

The mechanism makes authorization context travel with every data operation instead
of assuming ambient session state. It models RLS/claim versions, tenant scope,
background-job delegation, expiry, and provenance as one deterministic contract.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


def _canonical(value: Any) -> str:
    def norm(v: Any) -> Any:
        if v is None or isinstance(v, (str, bool, int)):
            return v
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ValueError("non_finite_value")
            return v
        if isinstance(v, (list, tuple)):
            return [norm(x) for x in v]
        if isinstance(v, dict):
            if not all(isinstance(k, str) for k in v):
                raise ValueError("non_string_key")
            return {k: norm(v[k]) for k in sorted(v)}
        raise ValueError(f"unsupported_type:{type(v).__name__}")
    return json.dumps(norm(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class PolicyEnvelope:
    policy_id: str
    tenant_id: str
    subject_id: str
    allowed_tables: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    claims_version: int
    rls_version: int
    issued_at: float
    not_after: float
    provenance_parent: str | None = None
    delegated_background_job: bool = False

    def fingerprint(self) -> str:
        return _digest(self.__dict__)


@dataclass(frozen=True)
class DataOperation:
    operation_id: str
    tenant_id: str
    table: str
    operation: str
    required_claims_version: int
    required_rls_version: int
    background_job: bool = False
    parent_operation_id: str | None = None


@dataclass(frozen=True)
class PolicyDecisionReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    operation_id: str
    policy_fingerprint: str
    provenance_digest: str
    metrics: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "operation_id": self.operation_id,
            "policy_fingerprint": self.policy_fingerprint,
            "provenance_digest": self.provenance_digest,
            "metrics": self.metrics,
        }


class PolicyCarryingAiDataPlane:
    """Fail-closed policy propagation across foreground and background data work."""

    def __init__(self, *, max_policy_age_s: float = 3600.0):
        if not math.isfinite(max_policy_age_s) or max_policy_age_s <= 0:
            raise ValueError("invalid_max_policy_age")
        self.max_policy_age_s = float(max_policy_age_s)

    def evaluate(
        self,
        policy: PolicyEnvelope,
        operation: DataOperation,
        *,
        now: float,
        parent_receipt_digest: str | None = None,
    ) -> PolicyDecisionReceipt:
        if not math.isfinite(now):
            raise ValueError("non_finite_now")
        reasons: list[str] = []
        if not policy.policy_id.strip() or not policy.subject_id.strip() or not policy.tenant_id.strip():
            reasons.append("policy_identity_missing")
        if policy.not_after <= policy.issued_at:
            reasons.append("policy_lifetime_invalid")
        if now < policy.issued_at:
            reasons.append("policy_not_active")
        if now > policy.not_after:
            reasons.append("policy_expired")
        if now - policy.issued_at > self.max_policy_age_s:
            reasons.append("policy_snapshot_stale")
        if operation.tenant_id != policy.tenant_id:
            reasons.append("tenant_scope_mismatch")
        if operation.table not in policy.allowed_tables:
            reasons.append("table_not_authorized")
        if operation.operation not in policy.allowed_operations:
            reasons.append("operation_not_authorized")
        if operation.required_claims_version != policy.claims_version:
            reasons.append("claims_version_mismatch")
        if operation.required_rls_version != policy.rls_version:
            reasons.append("rls_version_mismatch")
        if operation.background_job and not policy.delegated_background_job:
            reasons.append("background_job_not_delegated")
        if operation.parent_operation_id and not parent_receipt_digest:
            reasons.append("parent_provenance_missing")

        policy_fp = policy.fingerprint()
        provenance = {
            "policy": policy_fp,
            "policy_parent": policy.provenance_parent,
            "operation_id": operation.operation_id,
            "operation_parent": operation.parent_operation_id,
            "parent_receipt": parent_receipt_digest,
        }
        return PolicyDecisionReceipt(
            decision=Decision.REFUSE if reasons else Decision.ALLOW,
            reasons=tuple(reasons or ["policy_chain_valid"]),
            operation_id=operation.operation_id,
            policy_fingerprint=policy_fp,
            provenance_digest=_digest(provenance),
            metrics={
                "claims_version": policy.claims_version,
                "rls_version": policy.rls_version,
                "background_job": operation.background_job,
                "policy_age_s": now - policy.issued_at,
            },
        )

    def evaluate_chain(
        self,
        policy: PolicyEnvelope,
        operations: Iterable[DataOperation],
        *,
        now: float,
    ) -> tuple[PolicyDecisionReceipt, ...]:
        receipts: list[PolicyDecisionReceipt] = []
        previous_digest: str | None = None
        for op in operations:
            receipt = self.evaluate(
                policy,
                op,
                now=now,
                parent_receipt_digest=previous_digest if op.parent_operation_id else None,
            )
            receipts.append(receipt)
            if receipt.decision is Decision.REFUSE:
                break
            previous_digest = _digest(receipt.as_dict())
        return tuple(receipts)


Mechanism = PolicyCarryingAiDataPlane
