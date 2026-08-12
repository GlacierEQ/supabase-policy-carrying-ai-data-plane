"""Adapter between the local policy model and the live Supabase RLS contract."""
from __future__ import annotations

from typing import Any
from uuid import UUID

try:  # package import
    from .policy_carrying_ai_data_plane import DataOperation, PolicyEnvelope
except ImportError:  # direct src-on-PYTHONPATH import used by the repository tests
    from policy_carrying_ai_data_plane import DataOperation, PolicyEnvelope


def _uuid_text(value: str, field: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"{field}_must_be_uuid") from exc


def jwt_claims_for_policy(policy: PolicyEnvelope) -> dict[str, str]:
    """Return custom JWT claims consumed by the deployed RLS policies.

    The local mechanism allows arbitrary subject strings. The deployed Supabase
    boundary uses `auth.uid()`, so the adapter deliberately requires a UUID subject.
    """
    return {
        "sub": _uuid_text(policy.subject_id, "subject_id"),
        "tenant_id": policy.tenant_id,
        "claims_version": str(policy.claims_version),
        "rls_version": str(policy.rls_version),
    }


def rpc_payload_for_operation(
    operation: DataOperation,
    *,
    policy_uuid: str,
    operation_uuid: str,
    parent_operation_uuid: str | None = None,
) -> dict[str, Any]:
    """Build arguments for `public.crystallization_admit_policy_operation`."""
    policy_id = _uuid_text(policy_uuid, "policy_uuid")
    op_id = _uuid_text(operation_uuid, "operation_uuid")
    parent_id = _uuid_text(parent_operation_uuid, "parent_operation_uuid") if parent_operation_uuid else None
    if operation.background_job and parent_id is None:
        raise ValueError("background_operation_requires_parent_uuid")
    if not operation.background_job and parent_id is not None:
        raise ValueError("foreground_operation_must_not_supply_parent_uuid")
    return {
        "p_policy_id": policy_id,
        "p_operation_id": op_id,
        "p_table_name": operation.table,
        "p_operation": operation.operation,
        "p_background_job": operation.background_job,
        "p_parent_operation_id": parent_id,
    }
