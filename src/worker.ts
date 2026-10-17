interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
}

const DEFAULT_CODE = '123456';

function json(data: any, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

async function hashPassword(code: string, salt: string): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(code), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 100_000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyCode(env: Env, code: string): Promise<boolean> {
  const row = await env.DB.prepare('SELECT password_hash FROM app_config WHERE id = 1').first<{ password_hash: string }>();
  if (!row || !row.password_hash) return code === DEFAULT_CODE;
  const [salt, hash] = row.password_hash.split(':');
  const computed = await hashPassword(code, salt);
  return computed === hash;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/config')) {
      try {
        // 1. PULL SETTINGS (GET)
        if (url.pathname === '/api/config' && request.method === 'GET') {
          const row = await env.DB.prepare('SELECT settings, password_hash, password_version, updated_at FROM app_config WHERE id = 1').first<any>();
          if (!row) return json({ ok: false, error: 'DB not initialized' }, 500);
          return json({
            ok: true,
            settings: JSON.parse(row.settings || '{}'),
            version: row.updated_at,
            updatedAt: row.updated_at,
            pwv: row.password_version,
            isDefault: !row.password_hash
          });
        }

        // 2. VERIFY CODE (POST)
        if (url.pathname === '/api/config/verify' && request.method === 'POST') {
          const body: any = await request.json().catch(() => ({}));
          if (!await verifyCode(env, body.code)) return json({ ok: false, error: 'Wrong code' }, 401);
          const row = await env.DB.prepare('SELECT password_version FROM app_config WHERE id = 1').first<any>();
          return json({ ok: true, pwv: row.password_version });
        }

        // 3. SAVE SETTINGS (POST)
        if (url.pathname === '/api/config/save' && request.method === 'POST') {
          const body: any = await request.json().catch(() => ({}));
          if (!await verifyCode(env, body.code)) return json({ ok: false, error: 'Wrong code' }, 401);
          
          const now = Date.now();
          const serialized = JSON.stringify(body.settings);
          await env.DB.prepare('UPDATE app_config SET settings = ?, updated_at = ? WHERE id = 1').bind(serialized, now).run();
          
          const row = await env.DB.prepare('SELECT password_hash, password_version FROM app_config WHERE id = 1').first<any>();
          return json({
            ok: true,
            settings: body.settings,
            version: now,
            updatedAt: now,
            pwv: row.password_version,
            isDefault: !row.password_hash
          });
        }

        // 4. CHANGE PASSWORD (POST)
        if (url.pathname === '/api/config/password' && request.method === 'POST') {
          const body: any = await request.json().catch(() => ({}));
          if (!await verifyCode(env, body.code)) return json({ ok: false, error: 'Wrong code' }, 401);
          
          const newCode = body.next;
          if (!newCode || newCode.length < 4) return json({ ok: false, error: 'Too short' }, 400);
          
          const salt = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');
          const hash = await hashPassword(newCode, salt);
          
          await env.DB.prepare('UPDATE app_config SET password_hash = ?, password_version = password_version + 1, updated_at = ? WHERE id = 1')
            .bind(`${salt}:${hash}`, Date.now()).run();
            
          const row = await env.DB.prepare('SELECT password_version FROM app_config WHERE id = 1').first<any>();
          return json({ ok: true, pwv: row.password_version });
        }
// --- SYNC ORDERS & PURCHASES ---
if (url.pathname === '/api/sync/pull' && request.method === 'GET') {
  const orders = await env.DB.prepare('SELECT id, data FROM orders').all();
  const purchases = await env.DB.prepare('SELECT id, data FROM purchases').all();
  return json({ ok: true, orders: orders.results || [], purchases: purchases.results || [] });
}

if (url.pathname === '/api/sync/push' && request.method === 'POST') {
  const body: any = await request.json().catch(() => ({}));
  if (!body || !body.type || !body.records) return json({ ok: false, error: 'Invalid data' }, 400);
  
  const table = body.type === 'orders' ? 'orders' : 'purchases';
  const now = Date.now();
  const stmt = env.DB.prepare(`INSERT OR REPLACE INTO ${table} (id, data, updated_at) VALUES (?, ?, ?)`);
  
  const batch = body.records.map((r: any) => stmt.bind(r.id, JSON.stringify(r), now));
  if (batch.length > 0) await env.DB.batch(batch);
  
  return json({ ok: true });
}
        return json({ ok: false, error: 'Not found' }, 404);
      } catch (e: any) {
        return json({ ok: false, error: e.message }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};