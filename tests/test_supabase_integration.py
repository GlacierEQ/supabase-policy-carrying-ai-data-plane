from __future__ import annotations

import pytest

from policy_carrying_ai_data_plane import DataOperation, PolicyEnvelope
from supabase_integration import jwt_claims_for_policy, rpc_payload_for_operation


def live_policy(**overrides):
    data = dict(
        policy_id="local-policy",
        tenant_id="crystal-tenant-a",
        subject_id="11111111-1111-1111-1111-111111111111",
        allowed_tables=("documents",),
        allowed_operations=("select", "insert"),
        claims_version=1,
        rls_version=1,
        issued_at=100.0,
        not_after=200.0,
        delegated_background_job=True,
    )
    data.update(overrides)
    return PolicyEnvelope(**data)


def test_policy_adapter_emits_supabase_rls_claim_shape():
    assert jwt_claims_for_policy(live_policy()) == {
        "sub": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "crystal-tenant-a",
        "claims_version": "1",
        "rls_version": "1",
    }


def test_foreground_rpc_payload_matches_deployed_function_contract():
    op = DataOperation(
        operation_id="local-op",
        tenant_id="crystal-tenant-a",
        table="documents",
        operation="select",
        required_claims_version=1,
        required_rls_version=1,
    )
    payload = rpc_payload_for_operation(
        op,
        policy_uuid="00000000-0000-0000-0000-000000001001",
        operation_uuid="20000000-0000-0000-0000-000000000010",
    )
    assert payload == {
        "p_policy_id": "00000000-0000-0000-0000-000000001001",
        "p_operation_id": "20000000-0000-0000-0000-000000000010",
        "p_table_name": "documents",
        "p_operation": "select",
        "p_background_job": False,
        "p_parent_operation_id": None,
    }


def test_background_rpc_payload_requires_parent_provenance():
    op = DataOperation(
        operation_id="local-bg",
        tenant_id="crystal-tenant-a",
        table="documents",
        operation="insert",
        required_claims_version=1,
        required_rls_version=1,
        background_job=True,
        parent_operation_id="local-parent",
    )
    with pytest.raises(ValueError, match="background_operation_requires_parent_uuid"):
        rpc_payload_for_operation(
            op,
            policy_uuid="00000000-0000-0000-0000-000000001001",
            operation_uuid="20000000-0000-0000-0000-000000000011",
        )

    payload = rpc_payload_for_operation(
        op,
        policy_uuid="00000000-0000-0000-0000-000000001001",
        operation_uuid="20000000-0000-0000-0000-000000000011",
        parent_operation_uuid="20000000-0000-0000-0000-000000000010",
    )
    assert payload["p_background_job"] is True
    assert payload["p_parent_operation_id"] == "20000000-0000-0000-0000-000000000010"


def test_non_uuid_subject_cannot_be_claimed_as_supabase_auth_uid():
    with pytest.raises(ValueError, match="subject_id_must_be_uuid"):
        jwt_claims_for_policy(live_policy(subject_id="human-label"))
