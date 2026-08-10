from __future__ import annotations

import math

import pytest

from policy_carrying_ai_data_plane import (
    DataOperation,
    Decision,
    PolicyCarryingAiDataPlane,
    PolicyEnvelope,
)


def policy(**overrides):
    data = dict(
        policy_id="p1", tenant_id="tenant-a", subject_id="user-1",
        allowed_tables=("documents",), allowed_operations=("select", "insert"),
        claims_version=7, rls_version=12, issued_at=100.0, not_after=200.0,
        delegated_background_job=True,
    )
    data.update(overrides)
    return PolicyEnvelope(**data)


def op(**overrides):
    data = dict(
        operation_id="op1", tenant_id="tenant-a", table="documents", operation="select",
        required_claims_version=7, required_rls_version=12,
    )
    data.update(overrides)
    return DataOperation(**data)


def test_valid_rls_claim_snapshot_allows_and_emits_provenance():
    receipt = PolicyCarryingAiDataPlane().evaluate(policy(), op(), now=150.0)
    assert receipt.decision is Decision.ALLOW
    assert len(receipt.policy_fingerprint) == 64
    assert len(receipt.provenance_digest) == 64


@pytest.mark.parametrize(
    "operation,reason",
    [
        (op(tenant_id="tenant-b"), "tenant_scope_mismatch"),
        (op(table="secrets"), "table_not_authorized"),
        (op(required_rls_version=13), "rls_version_mismatch"),
        (op(required_claims_version=8), "claims_version_mismatch"),
    ],
)
def test_scope_and_policy_version_mismatches_fail_closed(operation, reason):
    receipt = PolicyCarryingAiDataPlane().evaluate(policy(), operation, now=150.0)
    assert receipt.decision is Decision.REFUSE
    assert reason in receipt.reasons


def test_background_job_requires_explicit_delegation():
    receipt = PolicyCarryingAiDataPlane().evaluate(
        policy(delegated_background_job=False), op(background_job=True), now=150.0
    )
    assert receipt.decision is Decision.REFUSE
    assert "background_job_not_delegated" in receipt.reasons


def test_expired_or_stale_policy_snapshot_fails_closed():
    expired = PolicyCarryingAiDataPlane().evaluate(policy(), op(), now=201.0)
    assert expired.decision is Decision.REFUSE
    assert "policy_expired" in expired.reasons
    stale = PolicyCarryingAiDataPlane(max_policy_age_s=20).evaluate(policy(not_after=1000), op(), now=121.0)
    assert stale.decision is Decision.REFUSE
    assert "policy_snapshot_stale" in stale.reasons


def test_child_operation_requires_parent_provenance():
    child = op(operation_id="op2", parent_operation_id="op1")
    receipt = PolicyCarryingAiDataPlane().evaluate(policy(), child, now=150.0)
    assert receipt.decision is Decision.REFUSE
    assert "parent_provenance_missing" in receipt.reasons


def test_chain_stops_at_first_policy_violation():
    operations = [op(operation_id="op1"), op(operation_id="op2", parent_operation_id="op1"), op(operation_id="op3", table="secrets")]
    receipts = PolicyCarryingAiDataPlane().evaluate_chain(policy(), operations, now=150.0)
    assert [r.decision for r in receipts] == [Decision.ALLOW, Decision.ALLOW, Decision.REFUSE]


def test_non_finite_clock_is_rejected():
    with pytest.raises(ValueError, match="non_finite_now"):
        PolicyCarryingAiDataPlane().evaluate(policy(), op(), now=math.nan)
