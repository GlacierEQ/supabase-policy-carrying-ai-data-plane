from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "supabase/functions/crystallization-policy-operation/index.ts"


def test_edge_transport_preserves_caller_authorization_and_rls_rpc() -> None:
    source = EDGE.read_text(encoding="utf-8")
    assert "req.headers.get('Authorization')" in source
    assert "global: { headers: { Authorization: authorization } }" in source
    assert "crystallization_admit_policy_operation" in source
    assert "SUPABASE_ANON_KEY" in source
    assert "SERVICE_ROLE" not in source


def test_edge_transport_fails_closed_on_provenance_shape() -> None:
    source = EDGE.read_text(encoding="utf-8")
    assert "background_operation_requires_parent_operation_id" in source
    assert "foreground_operation_must_not_supply_parent_operation_id" in source
    assert "decision: 'REFUSE'" in source
    assert "rls_rpc_refused" in source


def test_edge_transport_does_not_claim_database_authority() -> None:
    source = EDGE.read_text(encoding="utf-8")
    assert ".rpc('crystallization_admit_policy_operation'" in source
    assert ".from(" not in source
