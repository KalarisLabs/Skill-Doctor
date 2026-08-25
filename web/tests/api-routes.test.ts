import { describe, expect, test } from 'vitest';
import { POST as createScan } from '../src/pages/api/scans/index';
import { GET as getReport } from '../src/pages/api/scans/[scanId]/report';
import { GET as getArtifact } from '../src/pages/api/artifacts/[...key]';
import { fakeD1, fakeEnv, fakeKV } from './helpers/d1';

function jsonRequest(body: unknown): Request {
  return new Request('https://doctor.kalarislabs.com/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
}

function routeContext(opts: { params?: Record<string, string>; request: Request; env?: unknown }) {
  const pending: Promise<unknown>[] = [];
  return {
    params: opts.params ?? {},
    request: opts.request,
    locals: {
      runtime: { env: opts.env ?? {} },
      cfContext: { waitUntil: (p: Promise<unknown>) => pending.push(p) }
    },
    _pending: pending
  } as any;
}

describe('S1: POST /api/scans', () => {
  test('valid source returns 202 with scan id and artifact coordinates', async () => {
    const d1 = fakeD1();
    const kv = fakeKV();
    const ctx = routeContext({
      request: jsonRequest({ source: '# skill\njust markdown\n' }),
      env: fakeEnv(d1.db, kv)
    });
    const res = await createScan(ctx);
    expect(res.status).toBe(202);

    const body = await res.json();
    expect(typeof body.scanId).toBe('string');
    expect(body.artifact.key).toBe(`scans/${body.scanId}/artifact.md`);
    expect(body.artifact.sha256).toMatch(/^[0-9a-f]{64}$/);

    await Promise.all(ctx._pending);
    expect(kv.store[body.artifact.key]).toBe('# skill\njust markdown\n');
    expect(d1.scanUpdates.some((u) => /status = 'done'/.test(u.sql))).toBe(true);
  });

  test('missing source is rejected with 400', async () => {
    const ctx = routeContext({
      request: jsonRequest({ layers: ['static'] }),
      env: fakeEnv(fakeD1().db, fakeKV())
    });
    const res = await createScan(ctx);
    expect(res.status).toBe(400);
  });

  test('SSRF targets are blocked with 403', async () => {
    for (const host of ['http://127.0.0.1/x', 'http://169.254.169.254/latest/meta-data']) {
      const ctx = routeContext({
        request: jsonRequest({ source: host }),
        env: fakeEnv(fakeD1().db, fakeKV())
      });
      const res = await createScan(ctx);
      expect(res.status).toBe(403);
    }
  });

  test('unprovisioned bindings fail loudly with 503, never silently succeed', async () => {
    const ctx = routeContext({
      request: jsonRequest({ source: 'harmless' }),
      env: {}
    });
    const res = await createScan(ctx);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toMatch(/not provisioned/i);
  });
});

describe('S2: GET /api/scans/[scanId]/report', () => {
  const DONE_ROW = {
    scan_id: 's-done',
    status: 'done',
    risk_level: 'CAUTION',
    risk_score: 4.5,
    layers_run: '["static"]',
    duration_ms: 42,
    bundle_hash: 'abc',
    created_at: '2026-08-25T00:00:00Z',
    updated_at: '2026-08-25T00:00:01Z',
    findings: '[{"id":"f1","severity":"HIGH","category":"c","file":"f","description":"d","remediation":"r","engine":"yara","confidence":0.95}]'
  };

  test('completed scan serves persisted verdict and findings', async () => {
    const ctx = routeContext({
      params: { scanId: 's-done' },
      request: new Request('https://x/report'),
      env: fakeEnv(fakeD1({ scanRows: [DONE_ROW] }).db)
    });
    const res = await getReport(ctx);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.risk_level).toBe('CAUTION');
    expect(body.findings).toHaveLength(1);
    expect(body.findings[0].engine).toBe('yara');
  });

  test('unknown scan id yields 404', async () => {
    const ctx = routeContext({
      params: { scanId: 'nope' },
      request: new Request('https://x/report'),
      env: fakeEnv(fakeD1().db)
    });
    const res = await getReport(ctx);
    expect(res.status).toBe(404);
  });

  test('in-progress scan yields 202, not a fabricated report', async () => {
    const ctx = routeContext({
      params: { scanId: 's-run' },
      request: new Request('https://x/report'),
      env: fakeEnv(fakeD1({ scanRows: [{ scan_id: 's-run', status: 'running' }] }).db)
    });
    const res = await getReport(ctx);
    expect(res.status).toBe(202);
  });

  test('failed scan yields 409 conflict, not fake data', async () => {
    const ctx = routeContext({
      params: { scanId: 's-err' },
      request: new Request('https://x/report'),
      env: fakeEnv(fakeD1({ scanRows: [{ scan_id: 's-err', status: 'error' }] }).db)
    });
    const res = await getReport(ctx);
    expect(res.status).toBe(409);
  });
});

describe('S4: GET /api/artifacts/[...key]', () => {
  test('artifact inside scans namespace is served', async () => {
    const kv = fakeKV({ 'scans/s1/artifact.md': '# content' });
    const ctx = routeContext({
      params: { key: 'scans/s1/artifact.md' },
      request: new Request('https://x/artifacts/scans/s1/artifact.md'),
      env: fakeEnv(null, kv)
    });
    const res = await getArtifact(ctx);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('# content');
  });

  test('keys outside the scans namespace are denied', async () => {
    const ctx = routeContext({
      params: { key: 'secrets/api-keys.txt' },
      request: new Request('https://x/artifacts/secrets/api-keys.txt'),
      env: fakeEnv(null, fakeKV())
    });
    const res = await getArtifact(ctx);
    expect(res.status).toBe(403);
  });

  test('missing artifact yields 404', async () => {
    const ctx = routeContext({
      params: { key: 'scans/ghost/artifact.md' },
      request: new Request('https://x/artifacts/scans/ghost/artifact.md'),
      env: fakeEnv(null, fakeKV())
    });
    const res = await getArtifact(ctx);
    expect(res.status).toBe(404);
  });

  test('unprovisioned storage fails loudly', async () => {
    const ctx = routeContext({
      params: { key: 'scans/s1/artifact.md' },
      request: new Request('https://x/artifacts/scans/s1/artifact.md'),
      env: {}
    });
    const res = await getArtifact(ctx);
    expect(res.status).toBe(503);
  });
});
