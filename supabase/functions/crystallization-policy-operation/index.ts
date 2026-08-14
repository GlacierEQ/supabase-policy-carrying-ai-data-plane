import { createClient } from 'npm:@supabase/supabase-js@2'

const headers = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

type OperationRequest = {
  policy_id?: string
  operation_id?: string
  table_name?: string
  operation?: string
  background_job?: boolean
  parent_operation_id?: string | null
}

function fail(status: number, error: string) {
  return new Response(JSON.stringify({ decision: 'REFUSE', error }), { status, headers })
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers })
  if (req.method !== 'POST') return fail(405, 'method_not_allowed')

  const authorization = req.headers.get('Authorization')
  if (!authorization) return fail(401, 'missing_authorization')

  const body = await req.json().catch(() => null) as OperationRequest | null
  if (!body) return fail(400, 'invalid_json')

  const policyId = body.policy_id?.trim()
  const operationId = body.operation_id?.trim()
  const tableName = body.table_name?.trim()
  const operation = body.operation?.trim()
  const backgroundJob = body.background_job === true
  const parentOperationId = body.parent_operation_id?.trim() || null

  if (!policyId || !operationId || !tableName || !operation) {
    return fail(400, 'policy_id_operation_id_table_name_and_operation_required')
  }
  if (backgroundJob && !parentOperationId) {
    return fail(400, 'background_operation_requires_parent_operation_id')
  }
  if (!backgroundJob && parentOperationId) {
    return fail(400, 'foreground_operation_must_not_supply_parent_operation_id')
  }

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_ANON_KEY')!,
    { global: { headers: { Authorization: authorization } } },
  )

  const { data, error } = await supabase.rpc('crystallization_admit_policy_operation', {
    p_policy_id: policyId,
    p_operation_id: operationId,
    p_table_name: tableName,
    p_operation: operation,
    p_background_job: backgroundJob,
    p_parent_operation_id: parentOperationId,
  })

  if (error) {
    return new Response(JSON.stringify({
      decision: 'REFUSE',
      error: 'rls_rpc_refused',
      detail: error.message,
    }), { status: 403, headers })
  }

  return new Response(JSON.stringify({
    decision: 'ALLOW',
    transport: 'supabase_edge_function',
    rpc: 'crystallization_admit_policy_operation',
    receipt: data,
  }), { status: 200, headers })
})
