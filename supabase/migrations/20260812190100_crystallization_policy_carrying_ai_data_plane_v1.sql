-- Live Supabase RLS implementation for the Policy-Carrying AI Data Plane.
-- Applied to project ref kjebemdgvjvuutzvhbtp on 2026-08-12.
-- Isolated namespace: no existing application table is altered.

create schema if not exists crystallization_policy_data_plane;

revoke all on schema crystallization_policy_data_plane from public, anon, authenticated;
grant usage on schema crystallization_policy_data_plane to authenticated;

create or replace function crystallization_policy_data_plane.jwt_claim_text(claim_name text)
returns text
language sql
stable
set search_path = pg_catalog
as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb ->> claim_name
$$;

revoke all on function crystallization_policy_data_plane.jwt_claim_text(text) from public, anon;
grant execute on function crystallization_policy_data_plane.jwt_claim_text(text) to authenticated;

create table if not exists crystallization_policy_data_plane.policy_envelopes (
  policy_id uuid primary key,
  tenant_id text not null check (btrim(tenant_id) <> ''),
  subject_id uuid not null,
  allowed_tables text[] not null check (cardinality(allowed_tables) > 0),
  allowed_operations text[] not null check (cardinality(allowed_operations) > 0),
  claims_version integer not null check (claims_version > 0),
  rls_version integer not null check (rls_version > 0),
  issued_at timestamptz not null,
  not_after timestamptz not null,
  delegated_background_job boolean not null default false,
  provenance_parent text,
  created_at timestamptz not null default now(),
  check (not_after > issued_at)
);

create table if not exists crystallization_policy_data_plane.operation_receipts (
  operation_id uuid primary key,
  policy_id uuid not null references crystallization_policy_data_plane.policy_envelopes(policy_id) on delete restrict,
  tenant_id text not null,
  subject_id uuid not null,
  table_name text not null,
  operation text not null,
  required_claims_version integer not null,
  required_rls_version integer not null,
  background_job boolean not null default false,
  parent_operation_id uuid references crystallization_policy_data_plane.operation_receipts(operation_id) on delete restrict,
  policy_fingerprint text not null check (policy_fingerprint ~ '^[0-9a-f]{64}$'),
  provenance_digest text not null check (provenance_digest ~ '^[0-9a-f]{64}$'),
  decision text not null default 'ALLOW' check (decision = 'ALLOW'),
  created_at timestamptz not null default now()
);

alter table crystallization_policy_data_plane.policy_envelopes enable row level security;
alter table crystallization_policy_data_plane.policy_envelopes force row level security;
alter table crystallization_policy_data_plane.operation_receipts enable row level security;
alter table crystallization_policy_data_plane.operation_receipts force row level security;

drop policy if exists policy_envelope_visible_to_bound_subject on crystallization_policy_data_plane.policy_envelopes;
create policy policy_envelope_visible_to_bound_subject
on crystallization_policy_data_plane.policy_envelopes
for select
to authenticated
using (
  tenant_id = crystallization_policy_data_plane.jwt_claim_text('tenant_id')
  and subject_id::text = crystallization_policy_data_plane.jwt_claim_text('sub')
  and claims_version = coalesce(nullif(crystallization_policy_data_plane.jwt_claim_text('claims_version'), ''), '0')::integer
  and rls_version = coalesce(nullif(crystallization_policy_data_plane.jwt_claim_text('rls_version'), ''), '0')::integer
  and now() between issued_at and not_after
);

drop policy if exists operation_receipt_visible_to_bound_subject on crystallization_policy_data_plane.operation_receipts;
create policy operation_receipt_visible_to_bound_subject
on crystallization_policy_data_plane.operation_receipts
for select
to authenticated
using (
  tenant_id = crystallization_policy_data_plane.jwt_claim_text('tenant_id')
  and subject_id::text = crystallization_policy_data_plane.jwt_claim_text('sub')
  and required_claims_version = coalesce(nullif(crystallization_policy_data_plane.jwt_claim_text('claims_version'), ''), '0')::integer
  and required_rls_version = coalesce(nullif(crystallization_policy_data_plane.jwt_claim_text('rls_version'), ''), '0')::integer
);

drop policy if exists operation_receipt_insert_bound_policy on crystallization_policy_data_plane.operation_receipts;
create policy operation_receipt_insert_bound_policy
on crystallization_policy_data_plane.operation_receipts
for insert
to authenticated
with check (
  tenant_id = crystallization_policy_data_plane.jwt_claim_text('tenant_id')
  and subject_id::text = crystallization_policy_data_plane.jwt_claim_text('sub')
  and required_claims_version = coalesce(nullif(crystallization_policy_data_plane.jwt_claim_text('claims_version'), ''), '0')::integer
  and required_rls_version = coalesce(nullif(crystallization_policy_data_plane.jwt_claim_text('rls_version'), ''), '0')::integer
  and exists (
    select 1
    from crystallization_policy_data_plane.policy_envelopes p
    where p.policy_id = operation_receipts.policy_id
      and p.tenant_id = operation_receipts.tenant_id
      and p.subject_id = operation_receipts.subject_id
      and operation_receipts.table_name = any(p.allowed_tables)
      and operation_receipts.operation = any(p.allowed_operations)
      and operation_receipts.required_claims_version = p.claims_version
      and operation_receipts.required_rls_version = p.rls_version
      and now() between p.issued_at and p.not_after
      and (
        operation_receipts.background_job = false
        or (
          p.delegated_background_job = true
          and operation_receipts.parent_operation_id is not null
          and exists (
            select 1
            from crystallization_policy_data_plane.operation_receipts parent
            where parent.operation_id = operation_receipts.parent_operation_id
              and parent.policy_id = operation_receipts.policy_id
              and parent.tenant_id = operation_receipts.tenant_id
              and parent.subject_id = operation_receipts.subject_id
              and parent.decision = 'ALLOW'
          )
        )
      )
  )
);

revoke all on crystallization_policy_data_plane.policy_envelopes from public, anon, authenticated;
revoke all on crystallization_policy_data_plane.operation_receipts from public, anon, authenticated;
grant select on crystallization_policy_data_plane.policy_envelopes to authenticated;
grant select, insert on crystallization_policy_data_plane.operation_receipts to authenticated;

create or replace function public.crystallization_admit_policy_operation(
  p_policy_id uuid,
  p_operation_id uuid,
  p_table_name text,
  p_operation text,
  p_background_job boolean default false,
  p_parent_operation_id uuid default null
)
returns jsonb
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
declare
  p crystallization_policy_data_plane.policy_envelopes%rowtype;
  v_policy_fingerprint text;
  v_provenance_digest text;
begin
  select * into p
  from crystallization_policy_data_plane.policy_envelopes pe
  where pe.policy_id = p_policy_id
  limit 1;

  if not found then
    return jsonb_build_object(
      'decision', 'REFUSE',
      'reasons', jsonb_build_array('policy_not_visible_or_active'),
      'operation_id', p_operation_id
    );
  end if;

  v_policy_fingerprint := encode(extensions.digest(
    concat_ws('|', p.policy_id::text, p.tenant_id, p.subject_id::text,
      array_to_string(p.allowed_tables, ','), array_to_string(p.allowed_operations, ','),
      p.claims_version::text, p.rls_version::text, p.issued_at::text, p.not_after::text,
      p.delegated_background_job::text, coalesce(p.provenance_parent, '')),
    'sha256'
  ), 'hex');

  v_provenance_digest := encode(extensions.digest(
    concat_ws('|', v_policy_fingerprint, p_operation_id::text,
      coalesce(p_parent_operation_id::text, ''), p_table_name, p_operation, p_background_job::text),
    'sha256'
  ), 'hex');

  begin
    insert into crystallization_policy_data_plane.operation_receipts (
      operation_id, policy_id, tenant_id, subject_id, table_name, operation,
      required_claims_version, required_rls_version, background_job,
      parent_operation_id, policy_fingerprint, provenance_digest, decision
    ) values (
      p_operation_id, p.policy_id, p.tenant_id, p.subject_id, p_table_name, p_operation,
      p.claims_version, p.rls_version, p_background_job,
      p_parent_operation_id, v_policy_fingerprint, v_provenance_digest, 'ALLOW'
    );
  exception
    when insufficient_privilege then
      return jsonb_build_object(
        'decision', 'REFUSE',
        'reasons', jsonb_build_array('row_level_security_refused'),
        'operation_id', p_operation_id,
        'policy_fingerprint', v_policy_fingerprint
      );
    when unique_violation then
      return jsonb_build_object(
        'decision', 'REFUSE',
        'reasons', jsonb_build_array('operation_replay'),
        'operation_id', p_operation_id,
        'policy_fingerprint', v_policy_fingerprint
      );
  end;

  return jsonb_build_object(
    'decision', 'ALLOW',
    'reasons', jsonb_build_array('rls_policy_chain_valid'),
    'operation_id', p_operation_id,
    'policy_fingerprint', v_policy_fingerprint,
    'provenance_digest', v_provenance_digest,
    'background_job', p_background_job,
    'parent_operation_id', p_parent_operation_id
  );
end;
$$;

revoke all on function public.crystallization_admit_policy_operation(uuid, uuid, text, text, boolean, uuid) from public, anon;
grant execute on function public.crystallization_admit_policy_operation(uuid, uuid, text, text, boolean, uuid) to authenticated;

-- Synthetic proof fixture only. No production application data is used.
insert into crystallization_policy_data_plane.policy_envelopes (
  policy_id, tenant_id, subject_id, allowed_tables, allowed_operations,
  claims_version, rls_version, issued_at, not_after,
  delegated_background_job, provenance_parent
) values (
  '00000000-0000-0000-0000-000000001001',
  'crystal-tenant-a',
  '11111111-1111-1111-1111-111111111111',
  array['documents'], array['select','insert'], 1, 1,
  '2026-01-01T00:00:00Z', '2030-01-01T00:00:00Z', true,
  'crystallization-demo-root'
)
on conflict (policy_id) do update set
  tenant_id = excluded.tenant_id,
  subject_id = excluded.subject_id,
  allowed_tables = excluded.allowed_tables,
  allowed_operations = excluded.allowed_operations,
  claims_version = excluded.claims_version,
  rls_version = excluded.rls_version,
  issued_at = excluded.issued_at,
  not_after = excluded.not_after,
  delegated_background_job = excluded.delegated_background_job,
  provenance_parent = excluded.provenance_parent;
