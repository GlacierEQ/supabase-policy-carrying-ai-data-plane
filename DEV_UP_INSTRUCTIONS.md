# DEV_UP_INSTRUCTIONS — implementation receipt

**Repository:** `GlacierEQ/supabase-policy-carrying-ai-data-plane`  
**Company lens:** Supabase (independent; no affiliation)  
**Innovation:** Policy-Carrying AI Data Plane

## Completed implementation

The generic allow/refuse scaffold has been replaced by a domain mechanism that carries tenant scope, table/operation authority, claims version, RLS version, policy freshness, background-job delegation, and provenance through each operation.

### Shipped behavioral boundaries

- tenant isolation
- table and operation scope
- exact claims-version and RLS-version matching
- policy activation, expiry, and maximum snapshot age
- explicit background-job delegation
- parent-receipt provenance for child operations
- chain execution stops on first refusal
- deterministic policy/provenance digests
- non-finite clocks fail closed

## Verification contract

`python -m pytest -q` and `python scripts/operate.py` must both pass in CI. Passing those tests proves this deterministic reference mechanism only; it does not prove a live Supabase integration or production behavior.

## Remaining next gate

Integrate with a disposable Supabase project and bind the envelope to real Auth claims, RLS policies, and a delegated background job. Preserve the non-affiliation and no-production-claim boundary.
