"""Compatibility contract for the inverted promotion-authority seam."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.promotion_authority import create_readiness_receipt, validate_readiness_receipt


def test_historical_fixture_records_inversion_without_secret_reference():
    fixture = json.loads((ROOT / "machine/promotion_authority.json").read_text())
    assert fixture["status"] == "HISTORICAL_PROMOTION_AUTHORITY_INVERTED"
    assert fixture["replacement"] == "src/promotion_authority.py::ReadinessReceipt"
    assert "secret_ref" not in fixture


def test_compatibility_seam_creates_a_keyless_readiness_receipt():
    receipt = create_readiness_receipt(
        repository="GlacierEQ/supabase-policy-carrying-ai-data-plane",
        source_sha="compatibility-test-sha",
        capability="keyless advancement contract",
        evidence=["focused contract"],
        nonclaims=["not an external authorization"],
        next_action="prove current-head behavior",
    )
    assert validate_readiness_receipt(receipt) == (True, None)
