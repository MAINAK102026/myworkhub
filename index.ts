import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
});
function makePassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
}
function usernameEmail(username: string) {
  return `${username.toLowerCase()}@login.myworkhub.invalid`;
}
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  const url = Deno.env.get('SUPABASE_URL')!;
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const authHeader = req.headers.get('Authorization') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token) return json({ error: 'Sign in as the workspace owner first.' }, 401);

  const authClient = createClient(url, anonKey, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } });
  const { data: authData, error: authError } = await authClient.auth.getUser(token);
  if (authError || !authData.user) return json({ error: 'Invalid session.' }, 401);
  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: ownerProfile, error: ownerError } = await admin.from('profiles').select('is_owner').eq('id', authData.user.id).single();
  if (ownerError || !ownerProfile?.is_owner) return json({ error: 'Owner role required.' }, 403);

  let body: any;
  try { body = await req.json(); } catch { return json({ error: 'Invalid JSON request.' }, 400); }
  const backup = body?.backup;
  if (!backup || backup.version !== 3 || !backup.users || typeof backup.users !== 'object' || !backup.settings) {
    return json({ error: 'Expected a MyWorkHub v3 JSON backup.' }, 400);
  }

  const credentials: Array<{ username: string; temporary_password: string }> = [];
  const skipped: string[] = [];
  const failures: Array<{ username: string; reason: string }> = [];
  for (const [rawName, oldUser] of Object.entries(backup.users as Record<string, any>)) {
    const username = String(rawName).trim().toUpperCase();
    if (!/^[A-Z0-9_]{3,24}$/.test(username) || !oldUser || typeof oldUser !== 'object') {
      failures.push({ username: String(rawName), reason: 'Invalid username or record.' });
      continue;
    }
    const { data: existing } = await admin.from('profiles').select('id').eq('username', username).maybeSingle();
    if (existing) { skipped.push(username); continue; }
    const temporary_password = makePassword();
    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email: usernameEmail(username),
      password: temporary_password,
      email_confirm: true,
      user_metadata: { username, must_change_password: true },
    });
    if (createError || !created.user) {
      failures.push({ username, reason: createError?.message || 'Could not create account.' });
      continue;
    }
    const normalizedUser = { ...oldUser };
    // Legacy PINs and recovery dates are not authentication credentials in the cloud app.
    delete normalizedUser.pin;
    delete normalizedUser.recoveryDate;
    for (const key of ['attendance', 'tasks', 'learning', 'leave', 'reminders', 'notes']) {
      if (!Array.isArray(normalizedUser[key])) normalizedUser[key] = [];
    }
    const payload = {
      version: 3,
      users: { [username]: normalizedUser },
      settings: { monthlySalary: 0, currency: 'INR', workTargetHours: 8, ...(backup.settings || {}) },
      ownerEvents: credentials.length === 0 && Array.isArray(backup.ownerEvents) ? backup.ownerEvents.slice(0, 500) : [],
      createdAt: backup.createdAt || new Date().toISOString(),
      migratedAt: new Date().toISOString(),
    };
    const { error: workspaceError } = await admin.from('workspaces').upsert({
      user_id: created.user.id,
      username,
      payload,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id' });
    if (workspaceError) {
      await admin.auth.admin.deleteUser(created.user.id);
      failures.push({ username, reason: workspaceError.message });
      continue;
    }
    credentials.push({ username, temporary_password });
  }
  // Never log credentials. They are returned once so the owner can distribute them privately.
  return json({ created: credentials.length, skipped, failures, credentials });
});
