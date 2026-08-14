# Policy-Carrying AI Data Plane

Independent GlacierEQ portfolio implementation aligned to public Supabase/Postgres operating patterns.

> **Not affiliated.** This repository is not affiliated with, endorsed by, employed by, or deployed by Supabase.

## Purpose

AI work outlives foreground requests. Authorization therefore has to travel with the work rather than leaking out of ambient session state.

This repository now implements that contract in **three layers that agree**:

1. a deterministic Python policy/provenance evaluator;
2. a live Supabase/Postgres RLS enforcement surface deployed into an isolated schema in `supabase-glaciereq`; and
3. an authenticated Supabase Edge Function transport that preserves the caller JWT and routes admission through the same security-invoker RPC.

## Local policy engine

`PolicyEnvelope` binds:

- tenant and subject identity
- allowed table/operation scope
- claims version
- RLS version
- issue/expiry window
- delegated-background permission
- provenance parent

`PolicyCarryingAiDataPlane.evaluate()` fails closed on tenant/scope/version/freshness/delegation/provenance drift and emits deterministic policy/provenance digests. `evaluate_chain()` carries provenance from foreground work into dependent work and stops at the first refusal.

## Live Supabase RLS implementation

Migration: `supabase/migrations/20260812190100_crystallization_policy_carrying_ai_data_plane_v1.sql`

Applied project ref: `kjebemdgvjvuutzvhbtp` (`supabase-glaciereq`)

The migration is additive and isolated under `crystallization_policy_data_plane`. It does not modify existing application tables.

It creates:

- `policy_envelopes`
- `operation_receipts`
- forced RLS on both tables
- JWT-claim extraction for `sub`, `tenant_id`, `claims_version`, and `rls_version`
- tenant/subject/version/time-scoped policy visibility
- insert admission constrained by policy table/operation scope
- delegated background admission only when an allowed parent receipt exists
- one-shot operation IDs for replay refusal
- `public.crystallization_admit_policy_operation(...)` as a **SECURITY INVOKER** RPC, so the function cannot step around row security

## Live database proof executed 2026-08-12

Under the real Postgres `authenticated` role with request JWT claims set in-session:

| Case | Result |
|---|---|
| foreground `documents/select` | **ALLOW** / `rls_policy_chain_valid` |
| delegated background `documents/insert` with foreground parent | **ALLOW** / `rls_policy_chain_valid` |
| replay of the foreground operation UUID | **REFUSE** / `operation_replay` |
| same policy requested under another tenant claim | **REFUSE** / `policy_not_visible_or_active` |

Sanitized exact observations are preserved in `machine/live-supabase-rls-proof.json`.

A post-migration Supabase security-advisor snapshot produced **no finding against the new isolation schema**. Existing advisor findings elsewhere in the project are not claimed as this repository's behavior or repaired by this migration.

## Authenticated Edge transport deployed 2026-08-13

Function: `crystallization-policy-operation`

The function is deployed ACTIVE in `supabase-glaciereq` with platform JWT verification enabled. Repository source is preserved at `supabase/functions/crystallization-policy-operation/index.ts` and deployment metadata at `machine/live-supabase-edge-function-proof.json`.

The transport:

- requires an Authorization header;
- forwards that caller credential into `supabase-js` rather than using a service-role bypass;
- validates foreground/background parent-provenance shape before dispatch;
- invokes only `public.crystallization_admit_policy_operation(...)`;
- converts RPC/RLS rejection into an explicit `REFUSE` response;
- performs no direct table mutation.

This adds a real network transport surface without granting it authority beyond the already-proven RLS/RPC boundary.

## Python → Supabase adapter

`src/supabase_integration.py` converts local model objects into the concrete live boundary:

- `jwt_claims_for_policy(policy)` emits the custom claims consumed by RLS and requires a UUID-compatible Supabase subject identity.
- `rpc_payload_for_operation(...)` builds the arguments accepted by the deployed RPC and refuses background operations without parent UUID provenance.

This keeps the reference evaluator, Edge transport, and database enforcement from drifting into unrelated APIs with the same nouns.

## Verification

```bash
python -m pytest -q
python scripts/operate.py
```

CI covers the deterministic mechanism, adapter contract, and repository-owned Edge transport invariants. Live receipts record separately executed Supabase deployment/database evidence because public CI does not hold deployment credentials.

## Current boundary

**Proven now:** deterministic policy evaluation, policy-chain provenance, real Supabase/Postgres forced RLS, authenticated-role claim enforcement, real foreground admission, delegated background admission, replay refusal, tenant isolation, security-invoker RPC, and an ACTIVE JWT-verified Supabase Edge Function transport that preserves caller authorization into that RPC.

**Not yet claimed:** successful end-to-end network invocation using a real Supabase Auth-issued user token carrying the required custom claims; queue transport for delegated background work; production customer traffic; or production tenant adoption.

Those remaining integrations are explicit capability gaps, not hidden behind a green test badge.
