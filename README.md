# Policy-Carrying AI Data Plane

Independent GlacierEQ portfolio exhibit aligned to **Supabase** operating themes.

> **Not affiliated.** This repository is not affiliated with, endorsed by, employed by, or deployed at Supabase. No proprietary access, production deployment, customer impact, or company partnership is claimed.

## Problem

AI applications increasingly mix foreground requests, background jobs, embeddings, agents, permissions, and durable state. Ambient authorization becomes dangerous when work outlives the request that created it.

## Implemented mechanism

**Policy-Carrying AI Data Plane** binds each data operation to an explicit `PolicyEnvelope` containing tenant identity, subject, table/operation scope, RLS version, claims version, issuance/expiry, delegation permission, and provenance parent.

The evaluator fails closed when:

- tenant/table/operation scope diverges;
- claims or RLS versions drift;
- policy snapshots are inactive, expired, or stale;
- a background job lacks explicit delegation;
- a child operation lacks parent provenance.

Successful operations emit deterministic policy and provenance digests. `evaluate_chain()` propagates receipt provenance and stops at the first policy violation.

## Proof surface

- `src/policy_carrying_ai_data_plane.py` — domain mechanism
- `tests/test_policy_carrying_ai_data_plane.py` — scope, RLS/claims, freshness, delegation, provenance, chain tests
- `tests/test_adversarial.py` — generic estate adversarial lane
- `scripts/operate.py` — direct two-operation policy-chain execution
- `.github/workflows/tests.yml` — pytest + operate CI

## Current boundary

This is a deterministic reference implementation using synthetic policy envelopes. It does **not** connect to Supabase Auth, Postgres RLS, Edge Functions, queues, or a production tenant. Those integrations are the next evidence gate, not current claims.

## Next gate

Bind the envelope contract to a disposable Supabase project and prove policy-version propagation across a real RLS-protected foreground request and delegated background job.
