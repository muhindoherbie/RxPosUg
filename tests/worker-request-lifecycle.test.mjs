// Run the real Worker with a request-owned transport, without production data or secrets.
// Node's VM modules let us replace only external runtimes, keeping the Worker and
// its database adapter under test. Run with --experimental-vm-modules.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { AsyncLocalStorage } from 'node:async_hooks';
import { webcrypto } from 'node:crypto';
import { SourceTextModule, SyntheticModule, createContext } from 'node:vm';

const root = new URL('../worker/index.js', import.meta.url);

async function harness({ schemaFailures = 0 } = {}) {
  const requests = new AsyncLocalStorage();
  const clients = [];
  let schemaReads = 0;
  const tables = ['records', 'records_seq', 'records_t', 'records_gseq', 'tenants',
    'tenants_slug', 'login_fail', 'rtc', 'rtc_to', 'file_chunks', 'files',
    'owner_config', 'reset_codes'];
  const context = createContext({ Request, Response, URL, URLSearchParams,
    TextEncoder, TextDecoder, crypto: webcrypto, btoa, atob, console });
  const external = (values) => new SyntheticModule(Object.keys(values), function () {
    for (const [k, v] of Object.entries(values)) this.setExport(k, v);
  }, { context });
  const modules = new Map();
  function createClient(config) {
    const owner = requests.getStore();
    const client = {
      owner, config, ended: false,
      async execute({ sql, args }) {
        // Emulate Workers' invocation-owned network I/O. A shared client must
        // fail even if its previous invocation was still running or has ended.
        assert.equal(requests.getStore(), owner, 'database I/O escaped its request');
        assert.equal(client.ended, false, 'database client reused after request ended');
        await Promise.resolve();
        if (sql.includes('sqlite_master')) {
          schemaReads++;
          if (schemaFailures-- > 0) throw new Error('temporary schema read failure');
          return {
          columns: ['name', 'sql'], rows: tables.map(n => [n, n === 'tenants' ? 'slug branding' : '']), rowsAffected: 0,
          };
        }
        if (sql.startsWith('SELECT id FROM tenants WHERE key_hash')) return { columns: ['id'], rows: [['main']] };
        if (sql.startsWith('SELECT * FROM tenants WHERE id')) return { columns: ['id', 'status'], rows: [['main', 'active']] };
        if (sql.startsWith('SELECT t, id, rec, deleted, at, seq FROM records')) {
          assert.ok(args[3] <= 101, 'sync page exceeds CPU-safe record count');
          return { columns: ['t', 'id', 'rec', 'deleted', 'at', 'seq'], rows: Array.from({ length: args[3] }, (_, i) => ['products', String(i), '{"id":"' + i + '"}', 0, '2026-01-01', i + 1]) };
        }
        if (sql.includes("t = 'users'") || sql.includes('FROM login_fail')) {
          return { columns: [], rows: [], rowsAffected: 0 };
        }
        if (sql.startsWith('INSERT INTO login_fail')) return { columns: [], rows: [], rowsAffected: 1 };
        throw new Error('Unexpected SQL: ' + sql);
      },
    };
    clients.push(client);
    return client;
  }
  async function load(url) {
    if (modules.has(url.href)) return modules.get(url.href);
    const module = new SourceTextModule(await readFile(url, 'utf8'), { context, identifier: url.href });
    modules.set(url.href, module);
    await module.link(async (specifier, parent) => {
      if (specifier === '@libsql/client/web') return external({ createClient });
      if (specifier === 'cloudflare:workers') return external({ DurableObject: class {} });
      if (specifier.endsWith('.json')) return external({ default: JSON.parse(await readFile(new URL(specifier, parent.identifier), 'utf8')) });
      return load(new URL(specifier, parent.identifier));
    });
    return module;
  }
  const module = await load(root);
  await module.evaluate();
  let id = 0;
  async function invoke(path = '/api/health', init, overrides = {}) {
    const requestId = ++id;
    return requests.run(requestId, async () => {
      try {
        return await module.namespace.default.fetch(new Request('https://rxpos.test' + path, init), {
          DB_BACKEND: 'turso', TURSO_URL: 'https://database.test', TURSO_AUTH_TOKEN: 'test-token', ...overrides,
        });
      } finally {
        for (const client of clients) if (client.owner === requestId) client.ended = true;
      }
    });
  }
  return { invoke, clients, schemaReads: () => schemaReads };
}

test('a completed request cannot poison the next database request', async () => {
  const h = await harness();
  for (let i = 0; i < 3; i++) {
    const response = await h.invoke('/api/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.test', password: 'test-only' }),
    });
    assert.equal(response.status, 401, await response.clone().text());
  }
  assert.equal(h.clients.length, 3);
  assert.equal(h.schemaReads(), 1, 'completed schema metadata should be reused without sharing clients');
});

test('concurrent health, sign-in and authenticated API requests keep separate I/O', async () => {
  const h = await harness();
  const routes = Array.from({ length: 30 }, (_, i) => i % 3);
  const results = await Promise.all(routes.map(route => route === 0
    ? h.invoke()
    : route === 1 ? h.invoke('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'nobody@example.test', password: 'test-only' }) })
      : h.invoke('/api/config')));
  for (const [i, response] of results.entries()) {
    assert.equal(response.status, routes[i] === 0 ? 200 : 401, await response.clone().text());
  }
  assert.equal(h.clients.length, 30);
});

test('new requests use current database credentials', async () => {
  const h = await harness();
  assert.equal((await h.invoke()).status, 200);
  assert.equal((await h.invoke('/api/health', undefined, { TURSO_AUTH_TOKEN: 'rotated-test-token' })).status, 200);
  assert.equal(h.clients[1].config.authToken, 'rotated-test-token');
});

test('missing database configuration returns a controlled error', async () => {
  const h = await harness();
  const response = await h.invoke('/api/health', undefined, { TURSO_URL: '' });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, 'TURSO_URL is not set');
});

test('failed schema checks are retried by the next request', async () => {
  const h = await harness({ schemaFailures: 1 });
  assert.equal((await h.invoke()).status, 500);
  assert.equal((await h.invoke()).status, 200);
  assert.equal(h.schemaReads(), 2);
});

test('sync paginates remote records within the CPU-safe bound', async () => {
  const h = await harness();
  const response = await h.invoke('/api/sync', {
    method: 'POST', headers: { Authorization: 'Bearer test-only-key', 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'test-device', since: 0, changes: [] }),
  });
  assert.equal(response.status, 200, await response.clone().text());
  const data = await response.json();
  assert.equal(data.changes.length, 100);
  assert.equal(data.more, true);
  assert.equal(data.cursor, 100);
});
