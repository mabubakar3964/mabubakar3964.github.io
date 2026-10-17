interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
}

interface AppConfigRow {
  id: number;
  settings: string;
  password_hash: string | null;
  updated_at: number;
}

const DEFAULT_CODE = '123456';
const SESSION_TTL_MS = 4 * 60 * 60 * 1000;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function err(message: string, status = 400): Response {
  return json({ error: message }, status);
}

async function hashPassword(code: string, salt: string): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(code),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randHex(bytes: number): string {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getConfig(env: Env): Promise<AppConfigRow> {
  let row = await env.DB.prepare(
    'SELECT id, settings, password_hash, updated_at FROM app_config WHERE id = 1'
  ).first<AppConfigRow>();
  if (!row) {
    await env.DB.prepare(
      'INSERT INTO app_config (id, settings, password_hash, updated_at) VALUES (1, ?, NULL, ?)'
    ).bind('{}', Date.now()).run();
    row = await env.DB.prepare(
      'SELECT id, settings, password_hash, updated_at FROM app_config WHERE id = 1'
    ).first<AppConfigRow>();
  }
  return row!;
}

async function verifyCode(env: Env, code: string): Promise<boolean> {
  const cfg = await getConfig(env);
  if (!cfg.password_hash) return code === DEFAULT_CODE;
  const [salt, hash] = cfg.password_hash.split(':');
  if (!salt || !hash) return false;
  const computed = await hashPassword(code, salt);
  if (computed.length !== hash.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed.charCodeAt(i) ^ hash.charCodeAt(i);
  }
  return diff === 0;
}

async function issueSession(env: Env): Promise<{ token: string; expiresAt: number }> {
  const token = randHex(32);
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  await env.DB.prepare(
    'INSERT INTO admin_sessions (token, created_at, expires_at) VALUES (?, ?, ?)'
  ).bind(token, now, expiresAt).run();
  return { token, expiresAt };
}

async function requireAuth(env: Env, request: Request): Promise<Response | null> {
  const m = (request.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return err('Missing token', 401);
  const row = await env.DB.prepare(
    'SELECT token FROM admin_sessions WHERE token = ? AND expires_at > ?'
  ).bind(m[1], Date.now()).first<{ token: string }>();
  return row ? null : err('Invalid or expired token', 401);
}

async function handleVerify(req: Request, env: Env): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return err('Invalid JSON', 400); }
  const code = typeof body?.code === 'string' ? body.code.trim() : '';
  if (!code) return err('Missing code', 400);
  if (!(await verifyCode(env, code))) return err('Wrong code', 401);
  const s = await issueSession(env);
  return json({ ok: true, token: s.token, expiresAt: s.expiresAt });
}

async function handleSetCode(req: Request, env: Env): Promise<Response> {
  const authFail = await requireAuth(env, req);
  if (authFail) return authFail;
  let body: any;
  try { body = await req.json(); } catch { return err('Invalid JSON', 400); }
  const newCode = typeof body?.newCode === 'string' ? body.newCode.trim() : '';
  if (newCode.length < 4) return err('Code must be at least 4 characters', 400);
  const salt = randHex(16);
  const hash = await hashPassword(newCode, salt);
  await env.DB.prepare(
    'UPDATE app_config SET password_hash = ?, updated_at = ? WHERE id = 1'
  ).bind(`${salt}:${hash}`, Date.now()).run();
  await env.DB.prepare('DELETE FROM admin_sessions').run();
  return json({ ok: true });
}

async function handleGetSettings(env: Env): Promise<Response> {
  const cfg = await getConfig(env);
  let settings: unknown = {};
  try { settings = JSON.parse(cfg.settings); } catch { settings = {}; }
  const initialized = cfg.settings !== '{}' && Object.keys(settings as object).length > 0;
  return json({ settings, initialized, updatedAt: cfg.updated_at });
}

async function handleSetSettings(req: Request, env: Env): Promise<Response> {
  const authFail = await requireAuth(env, req);
  if (authFail) return authFail;
  let body: any;
  try { body = await req.json(); } catch { return err('Invalid JSON', 400); }
  if (!body || typeof body.settings !== 'object' || body.settings === null) {
    return err('Missing settings', 400);
  }
  const serialized = JSON.stringify(body.settings);
  const now = Date.now();
  await env.DB.prepare(
    'UPDATE app_config SET settings = ?, updated_at = ? WHERE id = 1'
  ).bind(serialized, now).run();
  return json({ ok: true, updatedAt: now });
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      const { pathname } = url;
      const method = request.method;
      try {
        if (pathname === '/api/config/verify' && method === 'POST') return await handleVerify(request, env);
        if (pathname === '/api/config/set' && method === 'POST') return await handleSetCode(request, env);
        if (pathname === '/api/settings/get' && method === 'GET') return await handleGetSettings(env);
        if (pathname === '/api/settings/set' && method === 'POST') return await handleSetSettings(request, env);
        return err('Not found', 404);
      } catch (e: any) {
        return err('Server error: ' + (e?.message ?? 'unknown'), 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};