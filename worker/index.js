// RxPOS cloud on Cloudflare Workers (free plan) + D1 — multi-pharmacy ("tenant") edition.
//   /api/sync              offline-first sync, per pharmacy (same protocol as server/hub.mjs)
//   /api/login             staff sign in with their RxPOS email + password (+ pharmacy code if the email is used at several)
//   /api/password/forgot   send a 6-digit reset code by email (Brevo, works with Gmail addresses) or SMS
//   /api/password/reset    set a new password with that code
//   /api/config            which integrations are switched on for this pharmacy
//   /api/pay/*             MTN MoMo + Airtel Money "request to pay" with THIS pharmacy's own merchant keys
//   /api/sms               SMS via Africa's Talking
//   /api/owner/*           owner console (vendor, web only): create pharmacies with their admin, web address, branches,
//                          features and keys; open, edit, export, import, reset or delete any pharmacy's data
//   /api/pharmacy/:slug    public name of the pharmacy at a web address (rxposug.com/<slug>)
//   /api/calendar/...ics   private calendar feed (events, refills due, expiring stock) for Google/Outlook/phones
// Everything else is the web app, served from ./dist.
//
// Secrets: SYNC_KEY (the original "main" pharmacy), OWNER_KEY (owner console), optional BREVO_API_KEY + BREVO_SENDER_EMAIL
// (+ BREVO_SENDER_NAME) for password emails, and payment/SMS keys for the main pharmacy (MTN_*, AIRTEL_*, AT_*).
// Other pharmacies' payment/SMS keys are stored per pharmacy (owner console → client → Payments & SMS).
import CATALOG from '../src/data/catalog.json' with { type: 'json' };
import { createClient } from '@libsql/client/web';
import { d1FromLibsql } from './libsql-d1.js';
import { isOwner, ownerAuthRoutes, ownerAccount, verifyGoogle, getConfig, ownerMainLogin, ownerMainFail } from './owner-auth.js';
export { TenantHub } from './live.js';
import { backup, restore } from './backup.js';

// Database: Cloudflare D1 (binding DB) by default, or libSQL / Turso when DB_BACKEND = "turso"
// (secrets TURSO_URL + TURSO_AUTH_TOKEN). The rest of the code doesn't know the difference.
function tursoDb(env) {
  if (env.TURSO_TEST_DB) return env.TURSO_TEST_DB; // tests: a local libSQL file instead of Turso
  if (!env.TURSO_URL) throw httpError(503, 'TURSO_URL is not set');
  // Workers I/O belongs to the current request; never share the client's pending
  // work between invocations (an ended request can leave other requests hung).
  return d1FromLibsql(createClient({ url: env.TURSO_URL, authToken: env.TURSO_AUTH_TOKEN }));
}
const withDatabase = (env) => ({ ...env, D1: env.DB, DB: env.DB_BACKEND === 'turso' ? tursoDb(env) : env.DB });

// Keep libSQL response decoding below the Workers Free CPU budget.
const PAGE = 100;
const MAX_PUSH = 500;
const TOKEN_DAYS = 30;
const MAIN = 'main';
// Tables only some roles may change; the server enforces it whatever a device sends
const GUARDED = { users: 'users.manage', roles: 'users.manage', settings: 'settings.manage' };
// Only the RxPOS owner (owner console) may change these: the licence/features and the pharmacy's branches
const SERVER_ONLY = new Set(['license', 'branches']);

const existingRec = async (db, tenant, t, id) => {
  const row = await db.prepare('SELECT rec FROM records WHERE tenant = ?1 AND k = ?2 AND deleted = 0').bind(tenant, t + '|' + id).first();
  return row ? JSON.parse(row.rec || 'null') : null;
};

/** Anyone may update their own user record (e.g. change their password), but never their role, status, branch or email. */
async function ownProfileEdit(db, tenant, who, ch) {
  if (!who.uid || String(ch.id) !== String(who.uid) || ch.deleted || !ch.rec) return false;
  const old = await existingRec(db, tenant, 'users', ch.id);
  if (!old) return false;
  return ['role', 'disabled', 'branchId', 'email'].every((f) => (old[f] ?? null) === (ch.rec[f] ?? null));
}

/** Administrator accounts are created only by the owner: a pharmacy may not add, promote to, or delete an admin. */
async function adminChangeRefused(db, tenant, ch) {
  const old = await existingRec(db, tenant, 'users', ch.id);
  if (ch.deleted) return old?.role === 'admin';
  if (ch.rec?.role !== 'admin') return false;
  return old?.role !== 'admin';
}

// Cache completed metadata only, never an invocation-owned in-flight promise.
const schemaReady = new Set();
/**
 * Create whatever tables/indexes are missing. It only reads when everything exists, so it costs no D1 writes
 * (the free plan allows 100,000 row writes a day, and every index multiplies the cost of each record write).
 */
async function ensureSchema(db, schemaKey = db) {
  if (schemaReady.has(schemaKey)) return;
  await (async () => {
    const { results } = await db.prepare("SELECT name, sql FROM sqlite_master WHERE type IN ('table', 'index')").all();
    const have = new Map(results.map((r) => [r.name, r.sql || '']));
    const ddl = [];
    if (!have.has('records')) ddl.push(`CREATE TABLE records (tenant TEXT NOT NULL, k TEXT NOT NULL, t TEXT NOT NULL, id TEXT NOT NULL, rec TEXT,
      deleted INTEGER NOT NULL DEFAULT 0, at TEXT NOT NULL, seq INTEGER NOT NULL, origin TEXT, PRIMARY KEY (tenant, k))`);
    if (!have.has('records_seq')) ddl.push('CREATE INDEX records_seq ON records(tenant, seq)');
    if (!have.has('records_t')) ddl.push('CREATE INDEX records_t ON records(tenant, t)');
    if (!have.has('records_gseq')) ddl.push('CREATE INDEX records_gseq ON records(seq)'); // fast MAX(seq) on every write
    if (have.has('records_type')) ddl.push('DROP INDEX records_type'); // not worth its write cost
    if (!have.has('tenants')) ddl.push(`CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT UNIQUE, features TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'active', secrets TEXT NOT NULL DEFAULT '{}', notes TEXT, created_at TEXT NOT NULL, slug TEXT, branding TEXT)`);
    else {
      if (!/\bslug\b/.test(have.get('tenants'))) ddl.push('ALTER TABLE tenants ADD COLUMN slug TEXT');
      if (!/\bbranding\b/.test(have.get('tenants'))) ddl.push('ALTER TABLE tenants ADD COLUMN branding TEXT'); // logo and allowed themes, set by the owner
    }
    if (!have.has('tenants_slug')) ddl.push('CREATE UNIQUE INDEX tenants_slug ON tenants(slug)');
    if (!have.has('login_fail')) ddl.push('CREATE TABLE login_fail (email TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL DEFAULT 0)');
    if (!have.has('rtc')) ddl.push('CREATE TABLE rtc (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, to_uid TEXT NOT NULL, from_uid TEXT NOT NULL, from_name TEXT, type TEXT NOT NULL, call_id TEXT NOT NULL, data TEXT, at INTEGER NOT NULL)');
    if (!have.has('rtc_to')) ddl.push('CREATE INDEX rtc_to ON rtc(tenant, to_uid, id)'); // instant look-up of calls waiting for a person
    if (!have.has('file_chunks')) ddl.push('CREATE TABLE file_chunks (tenant TEXT NOT NULL, id TEXT NOT NULL, n INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (tenant, id, n))');
    if (!have.has('files')) ddl.push('CREATE TABLE files (tenant TEXT NOT NULL, id TEXT NOT NULL, name TEXT, type TEXT, size INTEGER, chunks INTEGER, by_uid TEXT, at INTEGER, PRIMARY KEY (tenant, id))');
    if (!have.has('owner_config')) ddl.push('CREATE TABLE owner_config (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
    if (!have.has('reset_codes')) ddl.push('CREATE TABLE reset_codes (k TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0, window_start INTEGER NOT NULL DEFAULT 0)');
    // dropping an old index is optional: never let it block the API (e.g. when the daily write limit is reached)
    for (const sql of ddl) await db.prepare(sql).run().catch((e) => { if (!sql.startsWith('DROP')) throw e; });
  })();
  schemaReady.add(schemaKey);
}

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
};
const json = (body, status = 200) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...cors } });
const httpError = (status, message) => Object.assign(new Error(message), { status });

// ---------- crypto helpers ----------
const te = new TextEncoder();
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', te.encode(s)));
const randomKey = (n = 28) => b64url(crypto.getRandomValues(new Uint8Array(32))).replace(/[-_]/g, '').slice(0, n);
const safeEqual = (a, b) => { const x = te.encode(String(a)), y = te.encode(String(b)); return x.byteLength === y.byteLength && crypto.subtle.timingSafeEqual(x, y); };
const hmacKey = (env) => crypto.subtle.importKey('raw', te.encode('token:' + env.SYNC_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

async function signToken(env, payload) {
  const body = b64url(te.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), te.encode(body));
  return 'u.' + body + '.' + b64url(sig);
}
async function readToken(env, token) {
  const [, body, sig] = token.split('.');
  if (!body || !sig) return null;
  if (!(await crypto.subtle.verify('HMAC', await hmacKey(env), fromB64url(sig), te.encode(body)))) return null;
  const p = JSON.parse(new TextDecoder().decode(fromB64url(body)));
  return p.exp > Date.now() ? p : null;
}

async function pbkdf2(pw, saltB64, iter = 100000) {
  const key = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, key, 256));
}
async function verifyPassword(u, pw) {
  if (u.algo === 'pbkdf2') return (await pbkdf2(pw, u.salt, u.iter || 100000)) === u.hash;
  return (await sha256('pharmapos:' + pw)) === u.hash;
}

// ---------- tenants ----------
const DEFAULT_FEATURES = { catalog: true, branches: true, wholesale: true, proformas: true, prescriptions: true, finance: true, reports: true, reminders: true,
  chat: true, labels: true, import: true, reorder: true, transfers: true, momo: true, drugInfo: true, shifts: true,
  promos: true, hourly: true, calendar: true, weather: true, ai: true };

/** The original single-pharmacy deployment becomes tenant "main", keyed by the SYNC_KEY secret. */
let mainChecked = false; // once per Worker instance; writes only if the main pharmacy's sync key changed
async function ensureMainTenant(env) {
  if (!env.SYNC_KEY || mainChecked) return;
  const h = await sha256(env.SYNC_KEY);
  const cur = await env.DB.prepare("SELECT key_hash FROM tenants WHERE id = 'main'").first('key_hash');
  // Never re-creates "main": if the owner deleted it, it stays deleted (pharmacies are created in the owner console)
  if (cur && cur !== h) await env.DB.prepare("UPDATE tenants SET key_hash = ?1 WHERE id = 'main'").bind(h).run();
  mainChecked = true;
}
const tenantById = (env, id) => env.DB.prepare('SELECT * FROM tenants WHERE id = ?1').bind(id).first();
/** A pharmacy by its web address (slug) or its code */
const tenantByCode = (env, code) => env.DB.prepare('SELECT * FROM tenants WHERE slug = ?1 OR id = ?1 ORDER BY slug = ?1 DESC LIMIT 1').bind(code).first();
const slugify = (s) => String(s || '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
const RESERVED = new Set(['api', 'owner', 'assets', 'index', 'sw', 'manifest', 'favicon', 'admin', 'login', 'app', 'www']);

/** → { tenant, role, name, uid } for a valid pharmacy sync key or staff token; null otherwise */
async function authenticate(req, env) {
  const got = (req.headers.get('Authorization') || '').replace(/^Bearer /, '');
  if (!got) return null;
  let who = null;
  if (got.startsWith('u.')) {
    const p = await readToken(env, got).catch(() => null);
    if (p) who = { tenant: p.tn || MAIN, role: p.role, name: p.name, uid: p.sub };
  } else {
    const t = await env.DB.prepare('SELECT id FROM tenants WHERE key_hash = ?1').bind(await sha256(got)).first();
    if (t) who = { tenant: t.id, role: 'admin', name: 'sync key', viaKey: true };
  }
  if (!who) return null;
  const t = await tenantById(env, who.tenant);
  if (!t) return null;
  if (t.status !== 'active') throw httpError(403, 'This pharmacy account is suspended. Please contact your RxPOS provider.');
  // A staff token only counts while that person still exists (and isn't disabled) in this pharmacy: removed staff are
  // signed out at once, and a device from a deleted pharmacy can't push its old data into a new one with the same address
  if (who.uid) {
    const u = await env.DB.prepare('SELECT rec FROM records WHERE tenant = ?1 AND k = ?2 AND deleted = 0').bind(who.tenant, 'users|' + who.uid).first();
    if (!u || JSON.parse(u.rec || '{}').disabled) return null;
  }
  return { ...who, tenantRow: t };
}

/** Does this role (in this pharmacy) have the permission? Admin always does. */
async function roleCan(env, tenant, role, perm) {
  if (role === 'admin') return true;
  const r = await env.DB.prepare("SELECT rec FROM records WHERE tenant = ?1 AND t = 'roles' AND id = ?2 AND deleted = 0").bind(tenant, role).first();
  const rec = r?.rec ? JSON.parse(r.rec) : null;
  return !!rec?.permissions?.includes(perm);
}

/** Write a record from the server (license, password reset, owner actions) so devices pick it up on their next sync. */
async function serverWrite(env, tenant, t, id, rec, deleted = false) {
  const at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO records (tenant, k, t, id, rec, deleted, at, origin, seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'server', (SELECT COALESCE(MAX(seq), 0) + 1 FROM records))
    ON CONFLICT(tenant, k) DO UPDATE SET rec = excluded.rec, deleted = excluded.deleted, at = excluded.at, origin = 'server', seq = excluded.seq`)
    .bind(tenant, t + '|' + id, t, id, deleted ? null : JSON.stringify({ ...rec, id, updatedAt: at }), deleted ? 1 : 0, at).run();
}
const brandingOf = (t) => { try { return JSON.parse(t.branding || '{}'); } catch { return {}; } };
const writeLicense = (env, t) => serverWrite(env, t.id, 'license', 'license', { tenant: t.id, name: t.name, status: t.status, features: { ...DEFAULT_FEATURES, ...JSON.parse(t.features || '{}') }, branding: brandingOf(t) });

// ---------- login & password recovery ----------
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;

async function findUsers(env, email, tenant) {
  const q = tenant
    ? env.DB.prepare("SELECT tenant, rec FROM records WHERE t = 'users' AND deleted = 0 AND tenant = ?1").bind(tenant)
    : env.DB.prepare("SELECT tenant, rec FROM records WHERE t = 'users' AND deleted = 0");
  const { results } = await q.all();
  return results.map((r) => ({ tenant: r.tenant, u: JSON.parse(r.rec) })).filter((x) => x.u && x.u.email === email && !x.u.disabled);
}

async function pickUser(env, body) {
  const email = String(body.email || '').trim().toLowerCase().slice(0, 200);
  const code = body.tenant ? String(body.tenant).trim().toLowerCase() : '';
  const tenant = code ? (await tenantByCode(env, code))?.id || code : '';
  const found = await findUsers(env, email, tenant);
  if (found.length > 1) throw httpError(409, 'This email is used at more than one pharmacy. Enter your pharmacy code to continue.');
  return { email, tenant: found[0]?.tenant || tenant || MAIN, match: found[0] };
}

async function login(env, body) {
  // The owner can sign in here too (main page, no pharmacy chosen): owner email + owner password → owner console
  if (!body.tenant) {
    const own = await ownerMainLogin(env, body.email, body.password);
    if (own) {
      const res = await pharmacyLogin(env, body, own.match ? own.token : null);
      if ((res.status === 401 || res.status === 429) && own.owner && !own.locked) await ownerMainFail(env); // wrong owner password and no staff account opened either
      if (res.status === 401 && own.locked) return json({ error: 'Too many wrong passwords. Owner sign-in is locked for a few minutes; use the master key on the owner page.' }, 429);
      return res;
    }
  }
  return pharmacyLogin(env, body, null);
}

/** Staff sign-in. ownerToken: set when the same email + password is also the owner's (then the owner console is offered). */
async function pharmacyLogin(env, body, ownerToken) {
  const OWNER_CHOICE = { code: '__owner__', name: 'RxPOS owner', role: 'owner' };
  // One email at several pharmacies and no pharmacy chosen: the password decides which accounts are theirs, and if it
  // opens more than one the person picks the pharmacy. Nothing is revealed before the password is right.
  if (!body.tenant) {
    const email0 = String(body.email || '').trim().toLowerCase().slice(0, 200);
    const found = await findUsers(env, email0, '');
    if (found.length > 1) {
      const key = '*:' + email0;
      const fail = await env.DB.prepare('SELECT n, until FROM login_fail WHERE email = ?1').bind(key).first();
      if (fail && fail.until > Date.now()) {
        const mins = Math.ceil((fail.until - Date.now()) / 60000);
        return json({ error: `Too many wrong passwords. Try again in ${mins} minute${mins === 1 ? '' : 's'}, or use "Forgot password".` }, 429);
      }
      const ok = [];
      for (const f of found.slice(0, 10)) if (await verifyPassword(f.u, String(body.password || ''))) ok.push(f);
      if (!ok.length && ownerToken) return json({ owner: { token: ownerToken } });
      if (!ok.length) {
        const n = (fail && fail.until <= Date.now() && fail.until > 0 ? 0 : fail?.n || 0) + 1;
        const until = n >= MAX_FAILS ? Date.now() + LOCK_MINUTES * 60000 : 0;
        await env.DB.prepare('INSERT INTO login_fail (email, n, until) VALUES (?1, ?2, ?3) ON CONFLICT(email) DO UPDATE SET n = ?2, until = ?3').bind(key, until ? 0 : n, until).run();
        return json({ error: until ? `Too many wrong passwords. Sign-in is locked for ${LOCK_MINUTES} minutes.` : `Wrong email or password (${MAX_FAILS - n} attempt${MAX_FAILS - n === 1 ? '' : 's'} left before a ${LOCK_MINUTES}-minute lock).` }, until ? 429 : 401);
      }
      if (fail) await env.DB.prepare('DELETE FROM login_fail WHERE email = ?1').bind(key).run();
      const choices = [];
      for (const f of ok) {
        const t = await tenantById(env, f.tenant);
        if (t && t.status === 'active') choices.push({ code: t.slug || t.id, name: t.name, role: f.u.role || '' });
      }
      if (!choices.length && !ownerToken) return json({ error: 'This pharmacy account is suspended. Please contact your RxPOS provider.' }, 403);
      if (ownerToken) return json({ choose: [...choices.sort((a, b) => a.name.localeCompare(b.name)), OWNER_CHOICE], ownerToken });
      if (choices.length > 1) return json({ choose: choices.sort((a, b) => a.name.localeCompare(b.name)) });
      body = { ...body, tenant: choices[0].code };
    }
  }
  const { email, tenant, match } = await pickUser(env, body);
  const lockKey = tenant + ':' + email;
  const fail = await env.DB.prepare('SELECT n, until FROM login_fail WHERE email = ?1').bind(lockKey).first();
  if (fail && fail.until > Date.now()) {
    if (ownerToken) return json({ owner: { token: ownerToken } }); // staff account locked, but this is the owner's correct password
    const mins = Math.ceil((fail.until - Date.now()) / 60000);
    return json({ error: `Too many wrong passwords. Try again in ${mins} minute${mins === 1 ? '' : 's'}, or use "Forgot password".` }, 429);
  }
  if (!match || !(await verifyPassword(match.u, String(body.password || '')))) {
    if (ownerToken) return json({ owner: { token: ownerToken } }); // it is the owner's password: straight to the owner console
    const n = (fail && fail.until <= Date.now() && fail.until > 0 ? 0 : fail?.n || 0) + 1;
    const until = n >= MAX_FAILS ? Date.now() + LOCK_MINUTES * 60000 : 0;
    await env.DB.prepare('INSERT INTO login_fail (email, n, until) VALUES (?1, ?2, ?3) ON CONFLICT(email) DO UPDATE SET n = ?2, until = ?3').bind(lockKey, until ? 0 : n, until).run();
    return json({ error: until ? `Too many wrong passwords. Sign-in is locked for ${LOCK_MINUTES} minutes.` : `Wrong email or password (${MAX_FAILS - n} attempt${MAX_FAILS - n === 1 ? '' : 's'} left before a ${LOCK_MINUTES}-minute lock).` }, until ? 429 : 401);
  }
  const t = await tenantById(env, match.tenant);
  if (!t || t.status !== 'active') return ownerToken ? json({ owner: { token: ownerToken } }) : json({ error: 'This pharmacy account is suspended. Please contact your RxPOS provider.' }, 403);
  if (fail) await env.DB.prepare('DELETE FROM login_fail WHERE email = ?1').bind(lockKey).run();
  // the same email and password is also the owner's: let them choose the pharmacy or the owner console
  if (ownerToken) return json({ choose: [{ code: t.slug || t.id, name: t.name, role: match.u.role || '' }, OWNER_CHOICE], ownerToken });
  const u = match.u;
  const token = await signToken(env, { sub: u.id, tn: match.tenant, name: u.name, role: u.role, exp: Date.now() + TOKEN_DAYS * 864e5 });
  return json({ token, tenant: match.tenant, slug: t.slug || match.tenant, pharmacy: t.name, user: { id: u.id, name: u.name, email: u.email, role: u.role } });
}

const mask = (s, keep = 3) => (s.length <= keep ? '***' : s.slice(0, keep) + '***' + s.slice(-2));

async function sendEmail(env, to, subject, text) {
  if (!env.BREVO_API_KEY || !env.BREVO_SENDER_EMAIL) throw httpError(400, 'Password emails are not set up yet. Ask your administrator to reset your password.');
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST', headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ sender: { email: env.BREVO_SENDER_EMAIL, name: env.BREVO_SENDER_NAME || 'RxPOS' }, to: [{ email: to }], subject, textContent: text }),
  });
  if (!r.ok) throw httpError(502, 'The email could not be sent (' + r.status + ').');
}

async function forgotPassword(env, body) {
  const { email, tenant, match } = await pickUser(env, body);
  const channel = body.channel === 'sms' ? 'sms' : 'email';
  // Same answer whether or not the account exists, so this can't be used to discover staff emails
  const generic = { sent: true, channel, message: channel === 'sms' ? 'If that account has a phone number, a code is on its way by SMS.' : 'If that account exists, a code is on its way to its email inbox.' };
  if (!match) return json(generic);
  const k = tenant + ':' + email;
  const row = await env.DB.prepare('SELECT sent, window_start FROM reset_codes WHERE k = ?1').bind(k).first();
  const windowStart = row && Date.now() - row.window_start < 3600e3 ? row.window_start : Date.now();
  const sent = row && windowStart === row.window_start ? row.sent : 0;
  if (sent >= 3) return json({ error: 'Too many reset codes requested. Try again in an hour or ask your administrator.' }, 429);
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  const t = await tenantById(env, match.tenant);
  const text = `Your RxPOS password reset code for ${t?.name || 'your pharmacy'} is ${code}. It expires in 15 minutes. If you did not ask for this, ignore this message.`;
  if (channel === 'sms') {
    const phone = String(match.u.phone || '').replace(/\D/g, '');
    if (phone.length < 9) return json(generic);
    const res = await sendSms(providerEnv(env, t), { to: [phone.startsWith('0') ? '256' + phone.slice(1) : phone], message: text });
    if (!res.ok) throw httpError(502, 'SMS could not be sent. Try email or ask your administrator.');
  } else {
    await sendEmail(env, match.u.email, 'Your RxPOS password reset code', text);
  }
  await env.DB.prepare('INSERT INTO reset_codes (k, code_hash, expires, tries, sent, window_start) VALUES (?1, ?2, ?3, 0, ?4, ?5) ON CONFLICT(k) DO UPDATE SET code_hash = ?2, expires = ?3, tries = 0, sent = ?4, window_start = ?5')
    .bind(k, await sha256(k + ':' + code), Date.now() + 15 * 60000, sent + 1, windowStart).run();
  return json({ ...generic, hint: channel === 'sms' ? mask(String(match.u.phone || ''), 4) : mask(match.u.email) });
}

async function resetPassword(env, body) {
  const { email, tenant, match } = await pickUser(env, body);
  const pw = String(body.password || '');
  if (pw.length < 8) return json({ error: 'Use a password of at least 8 characters.' }, 400);
  const k = tenant + ':' + email;
  const row = await env.DB.prepare('SELECT * FROM reset_codes WHERE k = ?1').bind(k).first();
  if (!row || row.expires < Date.now() || row.tries >= 5) return json({ error: 'That code has expired. Request a new one.' }, 400);
  if (!match || !safeEqual(row.code_hash, await sha256(k + ':' + String(body.code || '').trim()))) {
    await env.DB.prepare('UPDATE reset_codes SET tries = tries + 1 WHERE k = ?1').bind(k).run();
    return json({ error: 'Wrong code.' }, 400);
  }
  const salt = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const u = { ...match.u, algo: 'pbkdf2', salt, iter: 100000, hash: await pbkdf2(pw, salt) };
  await serverWrite(env, match.tenant, 'users', u.id, u);
  await serverWrite(env, match.tenant, 'audit', crypto.randomUUID(), { date: new Date().toISOString(), user: u.name, action: 'Password reset (forgot password)', details: 'via ' + (body.channel || 'email') + ' code', branchId: 'main' });
  await env.DB.batch([env.DB.prepare('DELETE FROM reset_codes WHERE k = ?1').bind(k), env.DB.prepare('DELETE FROM login_fail WHERE email = ?1').bind(k)]);
  return json({ ok: true });
}

/** Forgot password: prove the account's Gmail / Google address with "Sign in with Google", then choose a new password */
async function resetWithGoogle(env, body) {
  const cfg = await getConfig(env.DB);
  if (!cfg.google_client_id) return json({ error: 'Google sign-in is not set up yet. Ask your administrator to reset your password.' }, 400);
  const pw = String(body.password || '');
  if (pw.length < 8) return json({ error: 'Use a password of at least 8 characters.' }, 400);
  let email;
  try { email = await verifyGoogle(body.credential, cfg.google_client_id); } catch (e) { return json({ error: e.message }, 401); }
  const { tenant, match } = await pickUser(env, { email, tenant: body.tenant });
  if (!match) return json({ error: `No RxPOS account uses ${email}. Use the Google account whose Gmail is on your RxPOS account.` }, 404);
  const salt = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const u = { ...match.u, algo: 'pbkdf2', salt, iter: 100000, hash: await pbkdf2(pw, salt) };
  delete u.mustChangePassword;
  await serverWrite(env, match.tenant, 'users', u.id, u);
  await serverWrite(env, match.tenant, 'audit', crypto.randomUUID(), { date: new Date().toISOString(), user: u.name, action: 'Password reset (Google)', details: email, branchId: 'main' });
  await env.DB.prepare('DELETE FROM login_fail WHERE email = ?1').bind(tenant + ':' + email).run();
  return json({ ok: true, email });
}

// ---------- sync ----------
async function sync(env, body, who) {
  const db = env.DB;
  const tenant = who.tenant;
  const { deviceId, since = 0, changes = [] } = body;
  if (!deviceId) return json({ error: 'Missing deviceId' }, 400);
  if (changes.length > MAX_PUSH) return json({ error: `Send at most ${MAX_PUSH} changes per request` }, 413);

  // Last writer wins per record; every accepted write gets the next sequence number.
  const upsert = db.prepare(
    `INSERT INTO records (tenant, k, t, id, rec, deleted, at, origin, seq)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, (SELECT COALESCE(MAX(seq), 0) + 1 FROM records))
     ON CONFLICT(tenant, k) DO UPDATE SET rec = excluded.rec, deleted = excluded.deleted, at = excluded.at, origin = excluded.origin, seq = excluded.seq
     WHERE excluded.at > records.at`
  );
  const allowed = {};
  const stmts = [];
  let refused = 0;
  for (const ch of changes) {
    if (!ch || typeof ch.t !== 'string' || ch.id == null || typeof ch.at !== 'string') continue;
    if (SERVER_ONLY.has(ch.t) && !who.viaKey) { refused++; continue; }
    const perm = GUARDED[ch.t];
    if (perm && !who.viaKey) {
      allowed[perm] ??= await roleCan(env, tenant, who.role, perm);
      if (!allowed[perm] && !(ch.t === 'users' && (await ownProfileEdit(db, tenant, who, ch)))) { refused++; continue; }
      if (ch.t === 'users' && (await adminChangeRefused(db, tenant, ch))) { refused++; continue; }
    }
    const id = String(ch.id);
    stmts.push(upsert.bind(tenant, ch.t + '|' + id, ch.t, id, ch.deleted ? null : JSON.stringify(ch.rec ?? null), ch.deleted ? 1 : 0, ch.at, deviceId));
  }
  let applied = 0;
  if (stmts.length) for (const r of await db.batch(stmts)) applied += r.meta.changes || 0;
  if (applied && env.HUB) await env.HUB.get(env.HUB.idFromName(tenant)).fetch('https://hub/notify', { method: 'POST', body: JSON.stringify({ from: deviceId }) }).catch(() => {});

  const { results } = await db
    .prepare('SELECT t, id, rec, deleted, at, seq FROM records WHERE tenant = ?1 AND seq > ?2 AND origin IS NOT ?3 ORDER BY seq LIMIT ?4')
    .bind(tenant, Number(since) || 0, deviceId, PAGE + 1)
    .all();
  const more = results.length > PAGE;
  const page = more ? results.slice(0, PAGE) : results;
  const cursor = more ? page[page.length - 1].seq : Math.max((await db.prepare('SELECT MAX(seq) m FROM records WHERE tenant = ?1').bind(tenant).first('m')) || 0, Number(since) || 0);
  // Build the response by hand so records stored as JSON text are not parsed and re-serialised (keeps CPU low)
  const items = page.map((r) => `{"t":${JSON.stringify(r.t)},"id":${JSON.stringify(r.id)},"at":${JSON.stringify(r.at)},"deleted":${r.deleted ? 'true' : 'false'},"rec":${r.rec ?? 'null'}}`);
  return json(`{"changes":[${items.join(',')}],"cursor":${cursor},"more":${more},"applied":${applied},"refused":${refused},"tenant":${JSON.stringify(tenant)}}`);
}

// ---------- Mobile Money (per pharmacy) ----------
/** Payment/SMS keys for a pharmacy: the main pharmacy uses the Worker secrets, client pharmacies their own stored keys. */
function providerEnv(env, t) {
  if (!t || t.id === MAIN) return env;
  return { ...JSON.parse(t.secrets || '{}'), AIRTEL_RELAY_URL: env.AIRTEL_RELAY_URL, AIRTEL_RELAY_KEY: env.AIRTEL_RELAY_KEY, __tenant: t.id };
}
const tokens = {};
async function cachedToken(name, fetcher) {
  const t = tokens[name];
  if (t && t.exp > Date.now() + 30000) return t.value;
  const { value, ttl } = await fetcher();
  tokens[name] = { value, exp: Date.now() + ttl * 1000 };
  return value;
}

const mtn = {
  enabled: (env) => !!(env.MTN_SUBSCRIPTION_KEY && env.MTN_API_USER && env.MTN_API_KEY),
  cfg(env) {
    const live = env.MTN_ENV === 'production';
    return { base: env.MTN_BASE_URL || (live ? 'https://proxy.momoapi.mtn.com' : 'https://sandbox.momodeveloper.mtn.com'), target: live ? env.MTN_TARGET || 'mtnuganda' : 'sandbox', currency: live ? env.MTN_CURRENCY || 'UGX' : 'EUR' };
  },
  token(env) {
    const c = mtn.cfg(env);
    return cachedToken('mtn:' + (env.__tenant || MAIN), async () => {
      const r = await fetch(c.base + '/collection/token/', { method: 'POST', headers: { Authorization: 'Basic ' + btoa(env.MTN_API_USER + ':' + env.MTN_API_KEY), 'Ocp-Apim-Subscription-Key': env.MTN_SUBSCRIPTION_KEY } });
      if (!r.ok) throw new Error(`MTN sign-in failed (${r.status})`);
      const j = await r.json();
      return { value: j.access_token, ttl: j.expires_in || 3000 };
    });
  },
  async request(env, { phone, amount, reference, note }) {
    const c = mtn.cfg(env);
    const ref = crypto.randomUUID();
    const r = await fetch(c.base + '/collection/v1_0/requesttopay', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + (await mtn.token(env)), 'X-Reference-Id': ref, 'X-Target-Environment': c.target, 'Ocp-Apim-Subscription-Key': env.MTN_SUBSCRIPTION_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: String(Math.round(amount)), currency: c.currency, externalId: reference, payer: { partyIdType: 'MSISDN', partyId: phone }, payerMessage: note.slice(0, 160), payeeNote: note.slice(0, 160) }),
    });
    if (r.status !== 202) throw new Error(`MTN refused the request (${r.status}) ${await r.text()}`.slice(0, 300));
    return ref;
  },
  async status(env, ref) {
    const c = mtn.cfg(env);
    const r = await fetch(`${c.base}/collection/v1_0/requesttopay/${ref}`, { headers: { Authorization: 'Bearer ' + (await mtn.token(env)), 'X-Target-Environment': c.target, 'Ocp-Apim-Subscription-Key': env.MTN_SUBSCRIPTION_KEY } });
    if (!r.ok) throw new Error(`MTN status check failed (${r.status})`);
    const j = await r.json();
    return { status: j.status === 'SUCCESSFUL' ? 'SUCCESSFUL' : j.status === 'FAILED' || j.status === 'REJECTED' ? 'FAILED' : 'PENDING', reason: j.reason || '', txid: j.financialTransactionId || '' };
  },
};

// Airtel only accepts calls from whitelisted server IPs. Workers have no fixed IP, so when AIRTEL_RELAY_URL is set
// every Airtel call goes through the RxPOS relay (relay/airtel-relay.mjs) running on a VM with a static IP.
async function airtelFetch(env, url, init = {}) {
  if (!env.AIRTEL_RELAY_URL) return fetch(url, init);
  const r = await fetch(env.AIRTEL_RELAY_URL.replace(/\/+$/, '') + '/forward', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Relay-Key': env.AIRTEL_RELAY_KEY || '' },
    body: JSON.stringify({ url, method: init.method || 'GET', headers: init.headers || {}, body: init.body }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('Airtel relay: ' + (j.error || r.status));
  return new Response(j.body, { status: j.status });
}

const airtel = {
  enabled: (env) => !!(env.AIRTEL_CLIENT_ID && env.AIRTEL_CLIENT_SECRET),
  cfg(env) {
    return { base: env.AIRTEL_ENV === 'production' ? 'https://openapi.airtel.africa' : 'https://openapiuat.airtel.africa', country: env.AIRTEL_COUNTRY || 'UG', currency: env.AIRTEL_CURRENCY || 'UGX' };
  },
  token(env) {
    const c = airtel.cfg(env);
    return cachedToken('airtel:' + (env.__tenant || MAIN), async () => {
      const r = await airtelFetch(env, c.base + '/auth/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: '*/*' }, body: JSON.stringify({ client_id: env.AIRTEL_CLIENT_ID, client_secret: env.AIRTEL_CLIENT_SECRET, grant_type: 'client_credentials' }) });
      if (!r.ok) throw new Error(`Airtel sign-in failed (${r.status})`);
      const j = await r.json();
      return { value: j.access_token, ttl: Number(j.expires_in) || 3000 };
    });
  },
  headers: async (env, c) => ({ Authorization: 'Bearer ' + (await airtel.token(env)), 'Content-Type': 'application/json', Accept: '*/*', 'X-Country': c.country, 'X-Currency': c.currency }),
  async request(env, { phone, amount, reference }) {
    const c = airtel.cfg(env);
    const id = reference.replace(/[^A-Za-z0-9]/g, '').slice(0, 20) + Date.now().toString(36).slice(-4).toUpperCase();
    const r = await airtelFetch(env, c.base + '/merchant/v1/payments/', {
      method: 'POST', headers: await airtel.headers(env, c),
      body: JSON.stringify({ reference: reference.slice(0, 64), subscriber: { country: c.country, currency: c.currency, msisdn: phone.replace(/^256/, '') }, transaction: { amount: Math.round(amount), country: c.country, currency: c.currency, id } }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.status?.success === false) throw new Error(`Airtel refused the request: ${j.status?.message || r.status}`);
    return id;
  },
  async status(env, ref) {
    const c = airtel.cfg(env);
    const r = await airtelFetch(env, `${c.base}/standard/v1/payments/${ref}`, { headers: await airtel.headers(env, c) });
    const j = await r.json().catch(() => ({}));
    const s = j.data?.transaction?.status;
    return { status: s === 'TS' ? 'SUCCESSFUL' : s === 'TF' || s === 'TE' ? 'FAILED' : 'PENDING', reason: j.data?.transaction?.message || '', txid: j.data?.transaction?.airtel_money_id || '' };
  },
};
const PROVIDERS = { mtn, airtel };

// ---------- SMS (Africa's Talking) ----------
async function sendSms(env, { to, message }) {
  if (!env.AT_USERNAME || !env.AT_API_KEY) return json({ error: 'SMS is not set up for this pharmacy yet.' }, 400);
  const list = (Array.isArray(to) ? to : [to]).map((p) => '+' + String(p).replace(/\D/g, '')).filter((p) => p.length > 9);
  if (!list.length || !message) return json({ error: 'Phone number and message are required.' }, 400);
  const sandbox = env.AT_USERNAME === 'sandbox';
  const form = new URLSearchParams({ username: env.AT_USERNAME, to: list.join(','), message: String(message).slice(0, 918) });
  if (env.AT_SENDER_ID) form.set('from', env.AT_SENDER_ID);
  const r = await fetch(`https://api.${sandbox ? 'sandbox.' : ''}africastalking.com/version1/messaging`, {
    method: 'POST', headers: { apiKey: env.AT_API_KEY, Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' }, body: form,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return json({ error: 'SMS provider error: ' + (j.SMSMessageData?.Message || r.status) }, 502);
  const recipients = j.SMSMessageData?.Recipients || [];
  return json({ sent: recipients.filter((x) => /success/i.test(x.status)).length, recipients: recipients.map((x) => ({ number: x.number, status: x.status, cost: x.cost })) });
}

// ---------- owner console (vendor) ----------
// Only the RxPOS owner (OWNER_KEY) creates pharmacies, their administrators and branches, sets their features and
// web address, and can open, edit, export, import, reset or delete any pharmacy's data.
const SECRET_FIELDS = ['MTN_SUBSCRIPTION_KEY', 'MTN_API_USER', 'MTN_API_KEY', 'MTN_ENV', 'MTN_TARGET', 'AIRTEL_CLIENT_ID', 'AIRTEL_CLIENT_SECRET', 'AIRTEL_ENV', 'AT_USERNAME', 'AT_API_KEY', 'AT_SENDER_ID'];
const KEEP_ON_RESET = "('products','formulations','expenseCategories','license','roles','branches','users','settings')";
const TABLE_RE = /^[A-Za-z]{2,30}$/;
const publicUser = ({ hash, salt, algo, iter, ...u }) => u; // eslint-disable-line no-unused-vars

async function passwordFields(pw) {
  if (String(pw).length < 8) throw httpError(400, 'Use a password of at least 8 characters.');
  const salt = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  return { algo: 'pbkdf2', salt, iter: 100000, hash: await pbkdf2(String(pw), salt) };
}

async function checkSlug(env, slug, exceptId = '') {
  if (!SLUG_RE.test(slug) || RESERVED.has(slug)) throw httpError(400, 'Web address: 2-40 lowercase letters, numbers or dashes, e.g. "citycare-ntinda".');
  const clash = await env.DB.prepare('SELECT id FROM tenants WHERE (slug = ?1 OR id = ?1) AND id != ?2').bind(slug, exceptId).first();
  if (clash) throw httpError(409, 'That web address is already used by another pharmacy.');
  return slug;
}

/** Write many records as the server in one batch (owner edits and imports reach devices at their next sync). */
async function serverWriteMany(env, tenant, items) {
  const db = env.DB;
  const stmt = db.prepare(`INSERT INTO records (tenant, k, t, id, rec, deleted, at, origin, seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'server', (SELECT COALESCE(MAX(seq), 0) + 1 FROM records))
    ON CONFLICT(tenant, k) DO UPDATE SET rec = excluded.rec, deleted = excluded.deleted, at = excluded.at, origin = 'server', seq = excluded.seq`);
  const now = new Date().toISOString();
  const stmts = items.map(({ t, id, rec, deleted }) => {
    const at = now;
    return stmt.bind(tenant, t + '|' + id, t, String(id), deleted ? null : JSON.stringify({ ...rec, id: String(id), updatedAt: at }), deleted ? 1 : 0, at);
  });
  for (let i = 0; i < stmts.length; i += 100) await db.batch(stmts.slice(i, i + 100));
  return stmts.length;
}

async function tenantUsers(env, tenant) {
  const { results } = await env.DB.prepare("SELECT rec FROM records WHERE tenant = ?1 AND t = 'users' AND deleted = 0").bind(tenant).all();
  return results.map((r) => JSON.parse(r.rec)).filter(Boolean);
}

async function owner(env, req, url, body) {
  if (!env.OWNER_KEY || env.OWNER_KEY.length < 20) throw httpError(503, 'The owner console is not enabled (OWNER_KEY secret missing).');
  if (!(await isOwner(env, (req.headers.get('Authorization') || '').replace(/^Bearer /, ''), safeEqual))) throw httpError(401, 'Owner sign-in expired or wrong. Sign in again.');
  const db = env.DB;
  const parts = url.pathname.split('/').slice(3).map(decodeURIComponent); // /api/owner/<...>
  if (parts[0] === 'move-to-turso') return moveToTurso(env, req, body);
  if (parts[0] === 'backup' && req.method === 'GET') return backup(env, url, json);
  if (parts[0] === 'restore' && req.method === 'POST') return restore(env, body, json);
  if (parts[0] === 'account') return ownerAccount(env, req, url, body || {}, { json });
  const view = async (t) => {
    const s = await db.prepare("SELECT COUNT(*) n, MAX(at) last, SUM(t = 'products' AND deleted = 0) products, SUM(t = 'users' AND deleted = 0) users, SUM(t = 'sales' AND deleted = 0) sales, SUM(t = 'branches' AND deleted = 0) branches FROM records WHERE tenant = ?1").bind(t.id).first();
    const secrets = JSON.parse(t.secrets || '{}');
    return { id: t.id, slug: t.slug || t.id, name: t.name, status: t.status, notes: t.notes || '', created: t.created_at, features: { ...DEFAULT_FEATURES, ...JSON.parse(t.features || '{}') }, branding: brandingOf(t),
      stats: { records: s.n || 0, products: s.products || 0, users: s.users || 0, sales: s.sales || 0, branches: s.branches || 0, lastActivity: s.last || null },
      payments: { mtn: t.id === MAIN ? mtn.enabled(env) : mtn.enabled(secrets), airtel: t.id === MAIN ? airtel.enabled(env) : airtel.enabled(secrets), sms: t.id === MAIN ? !!env.AT_API_KEY : !!secrets.AT_API_KEY } };
  };

  // ----- list & create -----
  if (parts[0] === 'tenants' && !parts[1] && req.method === 'GET') {
    const { results } = await db.prepare('SELECT * FROM tenants ORDER BY created_at').all();
    return json({ tenants: await Promise.all(results.map(view)) });
  }
  if (parts[0] === 'tenants' && !parts[1] && req.method === 'POST') {
    const name = String(body.name || '').trim().slice(0, 80);
    if (!name) return json({ error: 'Enter the pharmacy name.' }, 400);
    const slug = await checkSlug(env, String(body.slug || slugify(name)).trim().toLowerCase());
    if (await tenantById(env, slug)) return json({ error: 'That web address is already used.' }, 409);
    const admin = body.admin || {};
    const email = String(admin.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "Enter the administrator's email." }, 400);
    const pw = await passwordFields(admin.password || '');
    const key = randomKey();
    // The standard catalog is built into the apps (feature "catalog"), so nothing is copied: creating a pharmacy costs a few writes
    const features = JSON.stringify({ ...DEFAULT_FEATURES, ...(body.features || {}), ...(body.catalog === false ? { catalog: false } : {}) });
    await db.prepare('INSERT INTO tenants (id, name, key_hash, features, notes, created_at, slug) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?1)')
      .bind(slug, name, await sha256(key), features, String(body.notes || '').slice(0, 500), new Date().toISOString()).run();
    const t = await tenantById(env, slug);
    await writeLicense(env, t);
    const branches = [{ id: 'main', name: String(body.mainBranch || 'Main branch').slice(0, 60), address: String(body.address || '').slice(0, 120) },
      ...(Array.isArray(body.branches) ? body.branches : []).filter((b) => b?.name).slice(0, 20).map((b, i) => ({ id: 'br-' + slugify(b.name).slice(0, 20) + '-' + i, name: String(b.name).slice(0, 60), address: String(b.address || '').slice(0, 120) }))];
    const adminId = 'u-' + randomKey(10);
    await serverWriteMany(env, slug, [
      ...branches.map((b) => ({ t: 'branches', id: b.id, rec: b })),
      { t: 'settings', id: 'settings', rec: { name, address: String(body.address || ''), phone: String(body.phone || ''), currency: 'UGX', decimals: 0 } },
      { t: 'users', id: adminId, rec: { name: String(admin.name || 'Administrator').slice(0, 80), email, phone: String(admin.phone || ''), role: 'admin', ...pw, mustChangePassword: !!admin.mustChange } },
      { t: 'audit', id: crypto.randomUUID(), rec: { date: new Date().toISOString(), user: 'RxPOS owner', action: 'Pharmacy created', details: `${name} · admin ${email}`, branchId: 'main' } },
    ]);
    return json({ tenant: await view(t), syncKey: key });
  }

  const t = parts[1] && (await tenantById(env, parts[1]));
  if (parts[0] !== 'tenants' || !t) return json({ error: 'No such pharmacy.' }, 404);
  const sub = parts[2];

  // ----- details -----
  if (!sub && req.method === 'GET') {
    const users = (await tenantUsers(env, t.id)).map(publicUser);
    const { results: br } = await db.prepare("SELECT rec FROM records WHERE tenant = ?1 AND t = 'branches' AND deleted = 0").bind(t.id).all();
    const { results: tables } = await db.prepare('SELECT t, COUNT(*) n FROM records WHERE tenant = ?1 AND deleted = 0 GROUP BY t ORDER BY t').bind(t.id).all();
    const settings = await existingRec(db, t.id, 'settings', 'settings');
    return json({ tenant: await view(t), users, branches: br.map((r) => JSON.parse(r.rec)), tables, settings });
  }
  if (!sub && req.method === 'POST') {
    const name = body.name != null ? String(body.name).trim().slice(0, 80) || t.name : t.name;
    const slug = body.slug != null && body.slug !== (t.slug || t.id) ? await checkSlug(env, String(body.slug).trim().toLowerCase(), t.id) : t.slug || t.id;
    const status = ['active', 'suspended'].includes(body.status) ? body.status : t.status;
    const features = body.features ? JSON.stringify({ ...JSON.parse(t.features || '{}'), ...body.features }) : t.features;
    const notes = body.notes != null ? String(body.notes).slice(0, 500) : t.notes;
    let branding = brandingOf(t);
    if (body.branding) {
      const b = body.branding;
      if (b.logo !== undefined) {
        if (b.logo && (!/^data:image\/(png|jpeg|webp|svg\+xml);base64,/.test(b.logo) || b.logo.length > 200000)) return json({ error: 'The logo must be a PNG, JPG, WebP or SVG image under about 150 KB.' }, 400);
        branding.logo = b.logo || undefined;
      }
      if (b.themes !== undefined) {
        const list = Array.isArray(b.themes) ? b.themes.map(String).filter((x) => /^[a-z0-9-]{2,30}$/.test(x)).slice(0, 60) : [];
        if (list.length && list.length < 3) return json({ error: 'Allow at least 3 themes (or all).' }, 400);
        branding.themes = list.length ? list : undefined;
      }
      if (b.defaultTheme !== undefined) branding.defaultTheme = String(b.defaultTheme || '') || undefined;
      branding = JSON.parse(JSON.stringify(branding));
    }
    await db.prepare('UPDATE tenants SET name = ?2, status = ?3, features = ?4, notes = ?5, slug = ?6, branding = ?7 WHERE id = ?1').bind(t.id, name, status, features, notes, slug, JSON.stringify(branding)).run();
    const u = await tenantById(env, t.id);
    await writeLicense(env, u);
    if (name !== t.name) {
      const s = (await existingRec(db, t.id, 'settings', 'settings')) || {};
      await serverWriteMany(env, t.id, [{ t: 'settings', id: 'settings', rec: { ...s, name } }]);
    }
    return json({ tenant: await view(u) });
  }
  if (sub === 'delete' && req.method === 'POST') {
    if (body.confirm !== (t.slug || t.id)) return json({ error: `Type the web address "${t.slug || t.id}" to confirm.` }, 400);
    const r = await db.prepare('DELETE FROM records WHERE tenant = ?1').bind(t.id).run();
    await db.batch([
      db.prepare('DELETE FROM tenants WHERE id = ?1').bind(t.id),
      db.prepare("DELETE FROM login_fail WHERE email LIKE ?1 || ':%'").bind(t.id),
      db.prepare("DELETE FROM reset_codes WHERE k LIKE ?1 || ':%'").bind(t.id),
    ]);
    // its chat attachments go too (personal data must not outlive the pharmacy)
    await db.batch([db.prepare('DELETE FROM file_chunks WHERE tenant = ?1').bind(t.id), db.prepare('DELETE FROM files WHERE tenant = ?1').bind(t.id)]).catch(() => {});
    return json({ ok: true, deleted: r.meta.changes || 0 });
  }
  if (sub === 'rotate-key' && req.method === 'POST') {
    if (t.id === MAIN) return json({ error: 'The main pharmacy key is the SYNC_KEY secret; change it with "wrangler secret put SYNC_KEY".' }, 400);
    const key = randomKey();
    await db.prepare('UPDATE tenants SET key_hash = ?2 WHERE id = ?1').bind(t.id, await sha256(key)).run();
    return json({ syncKey: key, note: 'The old key stops working now. Staff signed in with their own accounts are not affected.' });
  }
  if (sub === 'secrets' && req.method === 'POST') {
    if (t.id === MAIN) return json({ error: 'The main pharmacy uses the Cloudflare secrets (deploy\\setup-mobile-money.ps1).' }, 400);
    const cur = JSON.parse(t.secrets || '{}');
    for (const f of SECRET_FIELDS) if (body[f] !== undefined) { if (body[f] === '') delete cur[f]; else cur[f] = String(body[f]).trim(); }
    await db.prepare('UPDATE tenants SET secrets = ?2 WHERE id = ?1').bind(t.id, JSON.stringify(cur)).run();
    return json({ tenant: await view(await tenantById(env, t.id)) });
  }
  if (sub === 'test-sms' && req.method === 'POST') {
    const to = String(body.to || '').replace(/\D/g, '');
    if (to.length < 9) return json({ error: 'Enter the phone number to send the test to.' }, 400);
    const res = await sendSms(providerEnv(env, t), { to: [to.startsWith('0') ? '256' + to.slice(1) : to], message: `RxPOS test: SMS for ${t.name} is working.` });
    return res;
  }
  if (sub === 'reset' && req.method === 'POST') {
    if (body.confirm !== (t.slug || t.id)) return json({ error: `Type the web address "${t.slug || t.id}" to confirm.` }, 400);
    const now = new Date().toISOString();
    const keep = body.keepMedicines === false ? "('license','roles','branches','users','settings')" : KEEP_ON_RESET;
    const m = (await db.prepare('SELECT COALESCE(MAX(seq), 0) m FROM records').first('m')) || 0;
    const r = await db.prepare(`UPDATE records SET deleted = 1, rec = NULL, at = ?2, origin = 'reset', seq = seq + ?3 WHERE tenant = ?1 AND deleted = 0 AND t NOT IN ${keep}
      AND NOT (t = 'customers' AND id = 'walk-in') AND NOT (t = 'banks' AND id = 'cash-drawer')`).bind(t.id, now, m).run();
    return json({ ok: true, cleared: r.meta.changes || 0 });
  }

  // ----- staff accounts (the owner creates each pharmacy's administrators) -----
  if (sub === 'users' && req.method === 'POST' && !parts[3]) {
    const u = body.user || {};
    const email = String(u.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: 'Enter a valid email.' }, 400);
    const users = await tenantUsers(env, t.id);
    const id = String(u.id || 'u-' + randomKey(10));
    if (users.some((x) => x.email === email && x.id !== id)) return json({ error: 'Another user at this pharmacy has that email.' }, 409);
    const old = users.find((x) => x.id === id) || {};
    if (!old.id && !u.password) return json({ error: 'Set a password for the new user.' }, 400);
    const rec = { ...old, name: String(u.name || old.name || '').slice(0, 80), email, phone: String(u.phone ?? old.phone ?? ''), role: String(u.role || old.role || 'cashier'),
      branchId: u.branchId ?? old.branchId ?? '', disabled: !!u.disabled, ...(u.password ? { ...(await passwordFields(u.password)), mustChangePassword: !!u.mustChange } : {}) };
    await serverWriteMany(env, t.id, [{ t: 'users', id, rec }, { t: 'audit', id: crypto.randomUUID(), rec: { date: new Date().toISOString(), user: 'RxPOS owner', action: old.id ? 'User updated by owner' : 'User created by owner', details: `${rec.name} (${rec.role})`, branchId: 'main' } }]);
    return json({ user: publicUser({ ...rec, id }) });
  }
  if (sub === 'users' && parts[4] === 'delete' && req.method === 'POST') {
    await serverWriteMany(env, t.id, [{ t: 'users', id: parts[3], deleted: true }]);
    return json({ ok: true });
  }

  // ----- branches -----
  if (sub === 'branches' && req.method === 'POST' && !parts[3]) {
    const b = body.branch || {};
    if (!String(b.name || '').trim()) return json({ error: 'Enter the branch name.' }, 400);
    const id = String(b.id || 'br-' + slugify(b.name).slice(0, 20) + '-' + randomKey(4).toLowerCase());
    const old = (await existingRec(db, t.id, 'branches', id)) || {};
    const rec = { ...old, name: String(b.name).trim().slice(0, 60), address: String(b.address ?? old.address ?? '').slice(0, 120), phone: String(b.phone ?? old.phone ?? ''), manager: String(b.manager ?? old.manager ?? '') };
    await serverWriteMany(env, t.id, [{ t: 'branches', id, rec }]);
    return json({ branch: { ...rec, id } });
  }
  if (sub === 'branches' && parts[4] === 'delete' && req.method === 'POST') {
    if (parts[3] === 'main') return json({ error: 'The main branch cannot be deleted.' }, 400);
    await serverWriteMany(env, t.id, [{ t: 'branches', id: parts[3], deleted: true }]);
    return json({ ok: true });
  }

  // ----- data browser: see and change any record -----
  if (sub === 'records' && req.method === 'GET') {
    const table = url.searchParams.get('t') || '';
    if (!TABLE_RE.test(table)) return json({ error: 'Choose a table.' }, 400);
    const q = (url.searchParams.get('q') || '').trim().slice(0, 80);
    const offset = Math.max(0, Number(url.searchParams.get('offset')) || 0);
    const where = 'tenant = ?1 AND t = ?2 AND deleted = 0' + (q ? ' AND rec LIKE ?3' : '');
    const args = q ? [t.id, table, '%' + q + '%'] : [t.id, table];
    const total = await db.prepare(`SELECT COUNT(*) n FROM records WHERE ${where}`).bind(...args).first('n');
    const { results } = await db.prepare(`SELECT id, at, rec FROM records WHERE ${where} ORDER BY at DESC LIMIT 50 OFFSET ${offset}`).bind(...args).all();
    const rows = results.map((r) => `{"id":${JSON.stringify(r.id)},"at":${JSON.stringify(r.at)},"rec":${r.rec ?? 'null'}}`);
    return json(`{"total":${total || 0},"rows":[${rows.join(',')}]}`);
  }
  if (sub === 'records' && req.method === 'POST') {
    const items = (Array.isArray(body.records) ? body.records : [body]).filter((x) => x && TABLE_RE.test(x.t || '') && x.id != null && x.t !== 'license');
    if (!items.length) return json({ error: 'Nothing to save.' }, 400);
    if (items.length > 500) return json({ error: 'Send at most 500 records at a time.' }, 413);
    for (const x of items) if (x.t === 'users' && x.rec?.password) { Object.assign(x.rec, await passwordFields(x.rec.password)); delete x.rec.password; }
    const n = await serverWriteMany(env, t.id, items.map((x) => ({ t: x.t, id: x.id, rec: x.rec || {}, deleted: !!x.deleted })));
    return json({ ok: true, written: n });
  }
  if (sub === 'export' && req.method === 'GET') {
    const { results } = await db.prepare('SELECT t, rec FROM records WHERE tenant = ?1 AND deleted = 0 ORDER BY t').bind(t.id).all();
    const groups = {};
    for (const r of results) (groups[r.t] ??= []).push(r.rec);
    const settings = groups.settings?.[0] || '{}';
    delete groups.settings;
    const out = Object.entries(groups).map(([k, v]) => `${JSON.stringify(k)}:[${v.join(',')}]`);
    return json(`{${out.join(',')}${out.length ? ',' : ''}"settings":${settings},"_meta":{"pharmacy":${JSON.stringify(t.name)},"exportedAt":"${new Date().toISOString()}"}}`);
  }
  return json({ error: 'Not found' }, 404);
}

// ---------- one-time copy of the whole cloud from D1 to Turso (owner only, in steps of 500 records) ----------
async function moveToTurso(env, req, body) {
  if (!env.TURSO_URL || !env.TURSO_AUTH_TOKEN) return json({ error: 'Add the TURSO_URL and TURSO_AUTH_TOKEN secrets first.' }, 400);
  const src = env.D1, dst = tursoDb(env);
  await ensureSchema(dst);
  const count = async (db) => ({
    tenants: await db.prepare('SELECT COUNT(*) n FROM tenants').first('n'),
    records: await db.prepare('SELECT COUNT(*) n FROM records').first('n'),
    maxSeq: (await db.prepare('SELECT MAX(seq) m FROM records').first('m')) || 0,
  });
  if (req.method === 'GET') return json({ d1: await count(src), turso: await count(dst), using: env.DB_BACKEND === 'turso' ? 'turso' : 'd1' });
  if (body.step === 'tenants') {
    const { results } = await src.prepare('SELECT * FROM tenants').all();
    await dst.batch(results.map((t) => dst.prepare('INSERT OR REPLACE INTO tenants (id, name, key_hash, features, status, secrets, notes, created_at, slug) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
      .bind(t.id, t.name, t.key_hash, t.features, t.status, t.secrets, t.notes, t.created_at, t.slug)));
    return json({ copied: results.length, done: true });
  }
  const after = Number(body.after) || 0;
  const { results } = await src.prepare('SELECT tenant, k, t, id, rec, deleted, at, seq, origin FROM records WHERE seq > ?1 ORDER BY seq LIMIT 500').bind(after).all();
  if (results.length) await dst.batch(results.map((r) => dst.prepare('INSERT OR REPLACE INTO records (tenant, k, t, id, rec, deleted, at, seq, origin) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
    .bind(r.tenant, r.k, r.t, r.id, r.rec, r.deleted, r.at, r.seq, r.origin)));
  return json({ copied: results.length, last: results.at(-1)?.seq ?? after, done: results.length < 500 });
}

// ---------- attachments in team messages (photos, PDFs, videos, audio, spreadsheets, voice notes) ----------
// Stored in the pharmacy's own database in pieces of up to 700 KB; links are signed so only people given the link can open them.
const MAX_FILE = 15 * 1024 * 1024;
const FILE_TYPES = /^(image\/|video\/|audio\/|application\/pdf$|text\/csv$|application\/vnd\.ms-excel$|application\/vnd\.openxmlformats-officedocument\.(spreadsheetml|wordprocessingml|presentationml)\.|application\/msword$|application\/vnd\.oasis\.opendocument\.)/;
async function fileSig(env, tenant, id) {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), te.encode('file:' + tenant + ':' + id));
  return b64url(sig).slice(0, 24);
}
async function uploadChunk(env, body, who) {
  const db = env.DB;
  const id = String(body.id || ''), n = Number(body.n), chunks = Number(body.chunks), size = Number(body.size);
  if (!/^[A-Za-z0-9_-]{8,40}$/.test(id) || !(n >= 0) || !(chunks >= 1) || n >= chunks || chunks > 40) return json({ error: 'Bad upload' }, 400);
  if (!(size > 0) || size > MAX_FILE) return json({ error: 'Files can be up to 15 MB.' }, 413);
  const type = String(body.type || 'application/octet-stream').split(';')[0];
  if (!FILE_TYPES.test(type)) return json({ error: 'That kind of file can’t be shared here.' }, 415);
  const bytes = Uint8Array.from(atob(String(body.data || '')), (c) => c.charCodeAt(0));
  if (!bytes.length || bytes.length > 800 * 1024) return json({ error: 'Bad upload piece' }, 400);
  await db.prepare('INSERT OR REPLACE INTO file_chunks (tenant, id, n, data) VALUES (?1, ?2, ?3, ?4)').bind(who.tenant, id, n, bytes).run();
  if (n === chunks - 1) {
    await db.prepare('INSERT OR REPLACE INTO files (tenant, id, name, type, size, chunks, by_uid, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)')
      .bind(who.tenant, id, String(body.name || 'file').slice(0, 120), type, size, chunks, who.uid || '', Date.now()).run();
    return json({ ok: true, done: true, path: '/api/files/' + who.tenant + '/' + id + '/' + (await fileSig(env, who.tenant, id)) });
  }
  return json({ ok: true });
}
async function downloadFile(env, tenant, id, sig) {
  if (!safeEqual(sig, await fileSig(env, tenant, id))) return json({ error: 'Not found' }, 404);
  const meta = await env.DB.prepare('SELECT name, type, size, chunks FROM files WHERE tenant = ?1 AND id = ?2').bind(tenant, id).first();
  if (!meta) return json({ error: 'Not found' }, 404);
  const { results } = await env.DB.prepare('SELECT data FROM file_chunks WHERE tenant = ?1 AND id = ?2 ORDER BY n').bind(tenant, id).all();
  const parts = results.map((r) => new Uint8Array(r.data));
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  const safeName = String(meta.name).replace(/[^\w. -]+/g, '_');
  return new Response(out, { headers: { 'Content-Type': meta.type, 'Content-Length': String(out.length), 'Content-Disposition': 'inline; filename="' + safeName + '"', 'Cache-Control': 'private, max-age=31536000, immutable', ...cors } });
}

// ---------- in-app voice calls between staff (WebRTC; the cloud only passes the call set-up messages) ----------
async function rtc(env, req, url, body, who) {
  const db = env.DB;
  if (url.pathname.endsWith('/config')) {
    const ice = [{ urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] }];
    if (env.TURN_URLS) ice.push({ urls: env.TURN_URLS.split(','), username: env.TURN_USERNAME, credential: env.TURN_CREDENTIAL });
    return json({ iceServers: ice });
  }
  if (!who.uid) return json({ error: 'Sign in with your own account to make calls.' }, 403);
  if (req.method === 'POST') {
    const type = String(body.type || '');
    if (!['ring', 'offer', 'answer', 'hangup', 'decline', 'busy'].includes(type) || !body.to || !body.callId) return json({ error: 'Bad call message' }, 400);
    const data = body.data ? JSON.stringify(body.data).slice(0, 60000) : null;
    await db.prepare('INSERT INTO rtc (tenant, to_uid, from_uid, from_name, type, call_id, data, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)')
      .bind(who.tenant, String(body.to), who.uid, who.name || '', type, String(body.callId).slice(0, 60), data, Date.now()).run();
    return json({ ok: true });
  }
  // GET: messages for me since an id (kept 2 minutes)
  const since = Number(url.searchParams.get('since')) || 0;
  const { results } = await db.prepare('SELECT id, from_uid, from_name, type, call_id, data, at FROM rtc WHERE tenant = ?1 AND to_uid = ?2 AND id > ?3 AND at > ?4 ORDER BY id LIMIT 50')
    .bind(who.tenant, who.uid, since, Date.now() - 120000).all();
  if (Math.random() < 0.02) await db.prepare('DELETE FROM rtc WHERE at < ?1').bind(Date.now() - 600000).run();
  const last = since || (await db.prepare('SELECT MAX(id) m FROM rtc').first('m')) || 0;
  return json({ messages: results.map((r) => ({ ...r, data: r.data ? JSON.parse(r.data) : null })), last: results.at(-1)?.id ?? last });
}

// ---------- AI (Cloudflare Workers AI, open models): prescription reading & drug quizzes ----------
// Mistral Small 3.1 (open source, Apache-2.0): reads images (typed & handwritten text) and writes well
const VISION = '@cf/mistralai/mistral-small-3.1-24b-instruct';
const TEXT = VISION;
const firstJson = (text, open = '{') => {
  // Some models already return parsed JSON instead of text
  if (text && typeof text === 'object') {
    if (open === '[' && !Array.isArray(text)) return Object.values(text).find(Array.isArray) || [];
    return text;
  }
  text = String(text || '');
  const close = open === '{' ? '}' : ']';
  const a = text.indexOf(open), b = text.lastIndexOf(close);
  if (a < 0 || b < a) throw new Error('The AI answer could not be read. Try again.');
  return JSON.parse(text.slice(a, b + 1));
};
async function runAi(env, model, input) {
  try { return await env.AI.run(model, input); }
  catch (e) {
    // Meta's licence for Llama 3.2 Vision has to be accepted once per account
    if (/agree/i.test(e.message)) { await env.AI.run(model, { prompt: 'agree' }).catch(() => {}); return env.AI.run(model, input); }
    throw e;
  }
}
async function ai(env, path, body, who) {
  if (!env.AI) return json({ error: 'AI is not set up on this cloud.' }, 503);
  const lic = JSON.parse(who.tenantRow.features || '{}');
  if (lic.ai === false) return json({ error: 'AI features are switched off for this pharmacy.' }, 403);
  if (path === '/api/ai/prescription') {
    const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(String(body.image || ''));
    if (!m || m[2].length > 2_000_000) return json({ error: 'Send a JPG or PNG photo under 1.5 MB.' }, 400);
    const prompt = 'You are helping a pharmacist in Uganda read a medical prescription (typed or handwritten). Read every medicine on it. ' +
      'Reply with ONLY this JSON, no other text: {"patient":"","prescriber":"","facility":"","date":"","diagnosis":"","medicines":[{"name":"","strength":"","form":"","dose":"","frequency":"","duration":"","quantity":"","unclear":false}],"notes":""}. ' +
      'Use generic or brand names exactly as written; expand common abbreviations (tds = three times a day, bd = twice a day, od = once a day, prn = when needed, stat = immediately). Set "unclear": true for anything hard to read. Leave unknown fields empty.';
    const out = await runAi(env, VISION, { messages: [{ role: 'user', content: [{ type: 'text', text: prompt }, { type: 'image_url', image_url: { url: body.image } }] }], max_tokens: 900, temperature: 0.1 });
    const parsed = firstJson(out.response);
    parsed.medicines = (Array.isArray(parsed.medicines) ? parsed.medicines : []).filter((x) => x && x.name).slice(0, 15);
    return json({ ...parsed, model: VISION });
  }
  if (path === '/api/ai/invoice') {
    // one page of a supplier's invoice / delivery note (PDF pages are turned into images on the device)
    const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(String(body.image || ''));
    if (!m || m[2].length > 2_000_000) return json({ error: 'Send a JPG or PNG image under 1.5 MB.' }, 400);
    const prompt = 'You are helping a pharmacy in Uganda enter a supplier invoice (or delivery note) into stock. Read this page carefully, including every product line in the table. ' +
      'Reply with ONLY this JSON, no other text: {"supplier":"","invoiceNo":"","date":"","items":[{"name":"","batch":"","expiry":"","qty":0,"unitCost":0,"lineTotal":0,"unclear":false}],"total":0}. ' +
      'Rules: "supplier" is the company that issued the invoice (not the buyer). "date" and "expiry" as YYYY-MM-DD (an expiry like 06/2028 or Jun-28 means the last day of that month). ' +
      '"name" is the product as written including strength and pack (e.g. "Amoxicillin 500mg caps 10x10"). "qty" is the quantity supplied, "unitCost" the price per unit/pack before the line total, "lineTotal" the amount for that line; plain numbers without commas or currency. ' +
      'Include every product line once; skip subtotal, tax, discount and total rows. Set "unclear": true for any line you could not read with confidence. Leave unknown fields empty or 0.';
    const out = await runAi(env, VISION, { messages: [{ role: 'user', content: [{ type: 'text', text: prompt }, { type: 'image_url', image_url: { url: body.image } }] }], max_tokens: 2500, temperature: 0.1 });
    const parsed = firstJson(out.response);
    const num = (v) => Number(String(v ?? '').replace(/[^0-9.-]/g, '')) || 0;
    parsed.items = (Array.isArray(parsed.items) ? parsed.items : []).filter((x) => x && x.name).slice(0, 80)
      .map((x) => ({ name: String(x.name).slice(0, 120), batch: String(x.batch || '').slice(0, 40), expiry: String(x.expiry || '').slice(0, 20), qty: num(x.qty), unitCost: num(x.unitCost), lineTotal: num(x.lineTotal), unclear: !!x.unclear }));
    return json({ supplier: String(parsed.supplier || '').slice(0, 120), invoiceNo: String(parsed.invoiceNo || '').slice(0, 40), date: String(parsed.date || '').slice(0, 20), items: parsed.items, total: num(parsed.total), model: VISION });
  }
  if (path === '/api/ai/quiz') {
    const drugs = (Array.isArray(body.drugs) ? body.drugs : []).map((d) => String(d).slice(0, 60)).filter(Boolean).slice(0, 10);
    if (drugs.length < 2) return json({ error: 'Need at least two medicines.' }, 400);
    const n = Math.min(10, Math.max(3, Number(body.count) || 8));
    const prompt = `Write ${n} multiple-choice questions to train pharmacy staff in Uganda about these medicines: ${drugs.join(', ')}. ` +
      'Cover what each is used for, important side effects, key counselling points, and common interactions or cautions. Use accurate, standard pharmacology (WHO / BNF level). ' +
      'Reply with ONLY a JSON array, no other text: [{"q":"question","options":["A","B","C","D"],"answer":0,"explain":"one short sentence why"}]. "answer" is the index (0-3) of the correct option. Each question has exactly 4 options and only one correct answer.';
    const out = await runAi(env, TEXT, { messages: [{ role: 'system', content: 'You are a careful clinical pharmacist and educator.' }, { role: 'user', content: prompt }], max_tokens: 2200, temperature: 0.4 });
    const qs = firstJson(out.response, '[').filter((x) => x && x.q && Array.isArray(x.options) && x.options.length === 4 && x.answer >= 0 && x.answer < 4).slice(0, n);
    if (!qs.length) return json({ error: 'The AI did not produce a usable quiz. Try again.' }, 502);
    return json({ questions: qs, model: TEXT });
  }
  return json({ error: 'Not found' }, 404);
}

// ---------- health alerts (WHO Disease Outbreak News) ----------
const NEAR = /uganda|kenya|tanzania|rwanda|burundi|south sudan|congo|ethiopia|somalia|africa/i;
async function healthAlerts() {
  const cache = caches.default;
  const key = new Request('https://rxpos.cache/health-alerts-v1');
  const hit = await cache.match(key).catch(() => null);
  if (hit) return hit;
  let r;
  try { r = await fetch('https://www.who.int/api/news/diseaseoutbreaknews?sf_culture=en&$orderby=PublicationDateAndTime%20desc&$top=12&$select=Title,PublicationDateAndTime,UrlName', { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) }); } catch { r = null; }
  if (!r?.ok) return json({ error: 'WHO alerts are unavailable right now', items: [] }, 502);
  const items = ((await r.json()).value || []).map((x) => ({ title: x.Title, date: String(x.PublicationDateAndTime).slice(0, 10), url: 'https://www.who.int/emergencies/disease-outbreak-news/item/' + x.UrlName, near: NEAR.test(x.Title) }));
  const res = new Response(JSON.stringify({ source: 'World Health Organization – Disease Outbreak News', items }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=10800', ...cors } });
  await cache.put(key, res.clone()).catch(() => {});
  return res;
}

// ---------- calendar feed (subscribe in Google Calendar, Outlook or the phone's calendar) ----------
async function calendarSig(env, tenant) {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), te.encode('calendar:' + tenant));
  return b64url(sig).slice(0, 24);
}
const icsText = (s) => String(s || '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');
const icsDate = (d) => d.replace(/-/g, '');
const addDays = (date, n) => new Date(new Date(date).getTime() + n * 864e5).toISOString().slice(0, 10);

async function calendarFeed(env, tenant) {
  const db = env.DB;
  const t = await tenantById(env, tenant);
  const rows = async (table) => (await db.prepare('SELECT rec FROM records WHERE tenant = ?1 AND t = ?2 AND deleted = 0').bind(tenant, table).all()).results.map((r) => JSON.parse(r.rec)).filter(Boolean);
  const today = new Date().toISOString().slice(0, 10);
  const horizon = addDays(today, 365);
  const ev = [];
  for (const e of await rows('events')) if (e.date) ev.push({ uid: 'ev-' + e.id, date: e.date, time: e.time, end: e.endTime, title: e.title, notes: e.notes, repeat: ['daily', 'weekly', 'monthly', 'yearly'].includes(e.repeat) ? e.repeat : '' });
  const customers = new Map((await rows('customers')).map((c) => [c.id, c.name]));
  for (const p of await rows('prescriptions')) {
    if (!p.refillDays || p.status !== 'Dispensed') continue;
    const due = addDays(p.dispensedOn || p.date, Number(p.refillDays));
    if (due >= addDays(today, -30) && due <= horizon) ev.push({ uid: 'rx-' + p.id + '-' + due, date: due, title: `Refill due: ${customers.get(p.customerId) || 'patient'}`, notes: p.medications });
  }
  // Expiring stock (only batches that still have stock)
  const { results: stock } = await db.prepare("SELECT json_extract(rec, '$.batchId') b, SUM(json_extract(rec, '$.qty')) q FROM records WHERE tenant = ?1 AND t = 'movements' AND deleted = 0 GROUP BY b HAVING q > 0").bind(tenant).all();
  const inStock = new Map(stock.map((s) => [s.b, s.q]));
  const batches = (await rows('batches')).filter((b) => b.expiry && b.expiry <= addDays(today, 180) && b.expiry >= addDays(today, -7) && inStock.get(b.id) > 0);
  if (batches.length) {
    const ids = [...new Set(batches.map((b) => b.productId))];
    const names = new Map();
    for (let i = 0; i < ids.length; i += 90) {
      const chunk = ids.slice(i, i + 90);
      const { results } = await db.prepare(`SELECT id, json_extract(rec, '$.name') name FROM records WHERE tenant = ?1 AND t = 'products' AND id IN (${chunk.map((_, j) => '?' + (j + 2)).join(',')})`).bind(tenant, ...chunk).all();
      for (const r of results) names.set(r.id, r.name);
    }
    for (const id of ids) if (!names.has(id) && /^cat-\d+$/.test(id)) names.set(id, CATALOG.rows[Number(id.slice(4)) - 1]?.[0]); // built-in catalog
    for (const b of batches) ev.push({ uid: 'exp-' + b.id, date: b.expiry, title: `Expires: ${names.get(b.productId) || 'medicine'} (batch ${b.batch}, ${inStock.get(b.id)} left)` });
  }
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//RxPOS//Pharmacy calendar//EN', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    `X-WR-CALNAME:${icsText((t?.name || 'Pharmacy') + ' · RxPOS')}`, 'REFRESH-INTERVAL;VALUE=DURATION:PT1H', 'X-PUBLISHED-TTL:PT1H'];
  for (const e of ev) {
    lines.push('BEGIN:VEVENT', `UID:${e.uid}@rxpos`, `DTSTAMP:${stamp}`);
    if (e.time) {
      const start = icsDate(e.date) + 'T' + e.time.replace(':', '') + '00';
      const endT = e.end && e.end > e.time ? e.end : `${String(Math.min(23, Number(e.time.slice(0, 2)) + 1)).padStart(2, '0')}${e.time.slice(2)}`;
      lines.push(`DTSTART:${start}`, `DTEND:${icsDate(e.date)}T${endT.replace(':', '')}00`);
    } else lines.push(`DTSTART;VALUE=DATE:${icsDate(e.date)}`, `DTEND;VALUE=DATE:${icsDate(addDays(e.date, 1))}`);
    if (e.repeat) lines.push(`RRULE:FREQ=${e.repeat.toUpperCase()}`);
    lines.push(`SUMMARY:${icsText(e.title)}`);
    if (e.notes) lines.push(`DESCRIPTION:${icsText(e.notes)}`);
    lines.push('END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  return new Response(lines.join('\r\n'), { headers: { 'Content-Type': 'text/calendar; charset=utf-8', 'Cache-Control': 'max-age=900', ...cors } });
}

export default {
  // Weekly: use the Brevo key once so Brevo never disables it for 90 days of inactivity (password emails are rare)
  async scheduled(event, env, ctx) {
    if (env.BREVO_API_KEY) ctx.waitUntil(fetch('https://api.brevo.com/v3/account', { headers: { 'api-key': env.BREVO_API_KEY, Accept: 'application/json' } }).then((r) => console.log('brevo keep-alive', r.status)).catch((e) => console.log('brevo keep-alive failed', e.message)));
  },
  async fetch(req, rawEnv) {
    const url = new URL(req.url);
    const path = url.pathname;
    if (!path.startsWith('/api/')) return rawEnv.ASSETS.fetch(req);
    let env;
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      env = withDatabase(rawEnv);
      await ensureSchema(env.DB, env.DB_BACKEND === 'turso' ? env.TURSO_URL : env.DB);
      await ensureMainTenant(env);
      if (path === '/api/health') return json({ ok: true, app: 'rxpos-cloud', configured: (env.SYNC_KEY || '').length >= 12, multiPharmacy: true, version: 5, database: env.DB_BACKEND === 'turso' ? 'turso' : 'd1' });
      // Public: latest WHO Disease Outbreak News (cached 3 h); outbreaks in or near Uganda are flagged
      if (path === '/api/health-alerts') return await healthAlerts();
      if (path === '/api/geo') {
        const cf = req.cf || {};
        return cf.latitude ? json({ lat: Number(cf.latitude), lon: Number(cf.longitude), city: cf.city || '', region: cf.region || '', country: cf.country || '' }) : json({ error: 'Location unknown' }, 404);
      }
      // Public: the name behind a pharmacy's web address, for its sign-in page
      const pm = path.match(/^\/api\/pharmacy\/([a-z0-9-]{1,40})$/);
      if (pm) {
        const t = await tenantByCode(env, pm[1]);
        return t ? json({ id: t.id, slug: t.slug || t.id, name: t.name, status: t.status, logo: brandingOf(t).logo || null }) : json({ error: 'No pharmacy at this address. Check the link with your RxPOS provider.' }, 404);
      }
      const fm = path.match(/^\/api\/files\/([a-z0-9-]{1,40})\/([A-Za-z0-9_-]{8,40})\/([A-Za-z0-9_-]{24})$/);
      if (fm && req.method === 'GET') return await downloadFile(env, fm[1], fm[2], fm[3]);
      const cm = path.match(/^\/api\/calendar\/([a-z0-9-]{1,40})\/([A-Za-z0-9_-]{24})\.ics$/);
      if (cm) {
        if (!safeEqual(cm[2], await calendarSig(env, cm[1]))) return json({ error: 'Not found' }, 404);
        return await calendarFeed(env, cm[1]);
      }
      if (path === '/api/live') {
        if (!env.HUB) return json({ error: 'Live connection not available' }, 503);
        const fake = new Request(req.url, { headers: { Authorization: 'Bearer ' + (url.searchParams.get('token') || '') } });
        const who = await authenticate(fake, env);
        if (!who?.uid) return json({ error: 'Not signed in' }, 401);
        const u = new URL('https://hub/live');
        u.search = new URLSearchParams({ uid: who.uid, name: who.name || '', device: url.searchParams.get('device') || '' }).toString();
        return env.HUB.get(env.HUB.idFromName(who.tenant)).fetch(new Request(u, req));
      }
      const body = req.method === 'POST' ? await req.json().catch(() => null) : null;
      if (req.method === 'POST' && !body) return json({ error: 'Bad request' }, 400);
      if (path === '/api/login' && req.method === 'POST') return await login(env, body);
      if (path === '/api/password/forgot' && req.method === 'POST') return await forgotPassword(env, body);
      if (path === '/api/password/reset' && req.method === 'POST') return await resetPassword(env, body);
      if (path === '/api/google-client') { const c = await getConfig(env.DB); return json({ clientId: c.google_client_id || null }); }
      if (path === '/api/password/google' && req.method === 'POST') return await resetWithGoogle(env, body);
      if (path.startsWith('/api/owner/')) return await owner(env, req, url, body);
      if (path.startsWith('/api/owner-auth/')) return await ownerAuthRoutes(env, req, url, body || {}, { json, safeEqual });

      const who = await authenticate(req, env);
      if (!who) return json({ error: 'Not signed in (wrong sync key or expired sign-in)' }, 401);
      const penv = providerEnv(env, who.tenantRow);

      if (path === '/api/sync' && req.method === 'POST') return await sync(env, body, who);
      if (path === '/api/config') return json({ tenant: who.tenant, slug: who.tenantRow.slug || who.tenant, pharmacy: who.tenantRow.name, mtn: mtn.enabled(penv), airtel: airtel.enabled(penv), sms: !!(penv.AT_USERNAME && penv.AT_API_KEY), email: !!(env.BREVO_API_KEY && env.BREVO_SENDER_EMAIL), mtnEnv: penv.MTN_ENV || 'sandbox', airtelEnv: penv.AIRTEL_ENV || 'uat', role: who.role });
      if (path === '/api/rtc' || path === '/api/rtc/config') return await rtc(env, req, url, body, who);
      if (path === '/api/files' && req.method === 'POST') return await uploadChunk(env, body, who);
      if (path.startsWith('/api/ai/') && req.method === 'POST') return await ai(env, path, body, who);
      if (path === '/api/calendar-link') return json({ url: `${url.origin}/api/calendar/${who.tenant}/${await calendarSig(env, who.tenant)}.ics` });
      if (path === '/api/pay/request' && req.method === 'POST') {
        const p = PROVIDERS[body.provider];
        if (!p?.enabled(penv)) return json({ error: `${body.provider === 'airtel' ? 'Airtel Money' : 'MTN MoMo'} is not set up for this pharmacy yet.` }, 400);
        const amount = Number(body.amount);
        if (!(amount > 0) || !body.phone) return json({ error: 'Phone and amount are required' }, 400);
        const ref = await p.request(penv, { phone: String(body.phone).replace(/\D/g, ''), amount, reference: String(body.reference || 'RxPOS'), note: String(body.note || 'RxPOS payment') });
        return json({ ref, provider: body.provider });
      }
      if (path === '/api/pay/status') {
        const p = PROVIDERS[url.searchParams.get('provider')];
        const ref = url.searchParams.get('ref');
        if (!p || !ref) return json({ error: 'provider and ref required' }, 400);
        return json(await p.status(penv, ref));
      }
      if (path === '/api/sms' && req.method === 'POST') return await sendSms(penv, body);
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: e.message || 'Server error' }, e.status || 500);
    }
  },
};
