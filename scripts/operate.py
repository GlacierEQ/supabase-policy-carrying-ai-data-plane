#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from policy_carrying_ai_data_plane import DataOperation, PolicyCarryingAiDataPlane, PolicyEnvelope


def main() -> int:
    policy = PolicyEnvelope(
        policy_id="demo-policy",
        tenant_id="tenant-demo",
        subject_id="agent-demo",
        allowed_tables=("documents",),
        allowed_operations=("select",),
        claims_version=3,
        rls_version=5,
        issued_at=100.0,
        not_after=200.0,
        delegated_background_job=True,
    )
    operations = (
        DataOperation("read-1", "tenant-demo", "documents", "select", 3, 5),
        DataOperation("read-2", "tenant-demo", "documents", "select", 3, 5, True, "read-1"),
    )
    receipts = PolicyCarryingAiDataPlane().evaluate_chain(policy, operations, now=150.0)
    payload = {"ok": all(r.decision.value == "ALLOW" for r in receipts), "receipts": [r.as_dict() for r in receipts]}
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
