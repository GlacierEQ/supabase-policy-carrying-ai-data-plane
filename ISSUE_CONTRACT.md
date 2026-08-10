# Issue contract — Policy-Carrying AI Data Plane

## Problem
keeping an integrated developer platform simple while AI apps introduce background jobs, embeddings, agents, permissions and rapidly growing state

## Desired outcome
A bounded, open, testable implementation of **Policy-Carrying AI Data Plane** that demonstrates Propagate row-level security identity and policy into embedding generation, retrieval, tool execution and generated artifacts so AI never leaves the authorization model of the source data.

## Non-goals
- Supabase affiliation or proprietary integration
- Portfolio-wide scale/performance claims
- UI marketing site

## Acceptance
1. Mechanism module implements allow + refuse with structured receipts
2. pytest behavioral suite green
3. operate.py cold-start produces JSON receipt
4. Non-affiliation disclaimer preserved
