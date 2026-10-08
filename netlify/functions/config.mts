import type { Config } from "@netlify/functions";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { db } from "../../db/index.js";
import { appConfig } from "../../db/schema.js";

// Used until the admin sets their own code from Settings → Admin Code.
const DEFAULT_CODE = "123456";
const MAX_BODY = 5_000_000;

const json = (data: unknown, status = 200) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store" } });

const hash = (code: string) => {
  const salt = randomBytes(16).toString("hex");
  return salt + ":" + scryptSync(code, salt, 32).toString("hex");
};

const matches = (code: string, stored: string | null) => {
  if (!stored) return code === DEFAULT_CODE;
  const [salt, h] = stored.split(":");
  const a = Buffer.from(h, "hex"), b = scryptSync(code, salt, 32);
  return a.length === b.length && timingSafeEqual(a, b);
};

async function row() {
  await db.insert(appConfig).values({ id: 1 }).onConflictDoNothing();
  const [r] = await db.select().from(appConfig).where(eq(appConfig.id, 1));
  return r;
}

const pub = (r: Awaited<ReturnType<typeof row>>) => ({
  version: r.version,
  settings: r.settings,
  pwv: r.passwordVersion,
  isDefault: !r.passwordHash,
  updatedAt: r.updatedAt,
});

async function body(req: Request) {
  const t = await req.text();
  if (t.length > MAX_BODY) throw new Error("too large");
  return JSON.parse(t || "{}");
}

// Slow down code guessing a little.
const deny = async () => {
  await new Promise((r) => setTimeout(r, 600));
  return json({ error: "Wrong code" }, 401);
};

export default async (req: Request) => {
  const action = new URL(req.url).pathname.split("/")[3] || "";

  if (req.method === "GET" && !action) return json(pub(await row()));
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  let b: any;
  try {
    b = await body(req);
  } catch {
    return json({ error: "Invalid request" }, 400);
  }
  const code = String(b.code ?? "");
  const r = await row();
  if (!matches(code, r.passwordHash)) return deny();

  if (action === "verify") return json({ ok: true, pwv: r.passwordVersion, isDefault: !r.passwordHash });

  if (action === "save") {
    if (!b.settings || typeof b.settings !== "object") return json({ error: "Invalid settings" }, 400);
    const [u] = await db
      .update(appConfig)
      .set({ settings: b.settings, version: sql`${appConfig.version} + 1`, updatedAt: new Date() })
      .where(eq(appConfig.id, 1))
      .returning();
    return json(pub(u));
  }

  if (action === "password") {
    const next = String(b.next ?? "").trim();
    if (next.length < 4 || next.length > 64) return json({ error: "Code must be 4–64 characters" }, 400);
    const [u] = await db
      .update(appConfig)
      .set({ passwordHash: hash(next), passwordVersion: sql`${appConfig.passwordVersion} + 1`, updatedAt: new Date() })
      .where(eq(appConfig.id, 1))
      .returning();
    return json({ ok: true, pwv: u.passwordVersion, isDefault: false });
  }

  return json({ error: "Not found" }, 404);
};

export const config: Config = {
  path: ["/api/config", "/api/config/:action"],
};
