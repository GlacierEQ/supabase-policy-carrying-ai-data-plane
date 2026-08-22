import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.promotion_authority import create_readiness_receipt, validate_readiness_receipt


def test_receipt_is_keyless_and_reproducible():
    receipt = create_readiness_receipt(
        repository="GlacierEQ/supabase-policy-carrying-ai-data-plane",
        source_sha="focused-test-sha",
        capability="policy propagation mechanism is ready for focused proof",
        evidence=["focused receipt contract passed"],
        nonclaims=["no external Supabase access is asserted"],
        next_action="run current-head deterministic proof",
    )
    assert validate_readiness_receipt(receipt) == (True, None)
    assert receipt.fingerprint() == receipt.fingerprint()
    assert "secret" not in repr(receipt).lower()


def test_receipt_requires_evidence_and_nonclaims():
    receipt = create_readiness_receipt(
        repository="GlacierEQ/example", source_sha="sha", capability="capability",
        evidence=[], nonclaims=[], next_action="frame next proof",
    )
    assert validate_readiness_receipt(receipt) == (False, "EVIDENCE_REQUIRED")
