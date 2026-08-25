import type { CloudflareEnv } from '../../src/lib/cloudflare';

export interface FakeD1 {
  db: unknown;
  events: Array<{ type: string; payload: any }>;
  scanUpdates: Array<{ sql: string; args: any[] }>;
}

export function fakeD1(options: { threats?: any[]; scanRows?: any[]; failOn?: RegExp } = {}): FakeD1 {
  const threats = options.threats ?? [];
  const scanRows = options.scanRows ?? [];
  const events: Array<{ type: string; payload: any }> = [];
  const scanUpdates: Array<{ sql: string; args: any[] }> = [];

  const db = {
    prepare(sql: string) {
      const failing = options.failOn?.test(sql) ?? false;
      return {
        bind(...args: any[]) {
          return {
            run: async () => {
              if (failing) throw new Error('injected d1 failure');
              if (/INSERT INTO scan_events/i.test(sql)) {
                events.push({ type: String(args[1]), payload: JSON.parse(String(args[2])) });
              } else if (/UPDATE scans/i.test(sql)) {
                scanUpdates.push({ sql, args });
              }
            },
            all: async () => {
              if (failing) throw new Error('injected d1 failure');
              if (/FROM threats/i.test(sql)) return { results: threats };
              if (/FROM scans/i.test(sql)) return { results: scanRows };
              return { results: [] };
            }
          };
        }
      };
    }
  };

  return { db, events, scanUpdates };
}

export function fakeKV(initial: Record<string, string> = {}) {
  const store = { ...initial };
  return {
    store,
    put: async (key: string, value: string) => { store[key] = value; },
    get: async (key: string) => store[key] ?? null
  };
}

export function fakeEnv(db: unknown | null, kv?: ReturnType<typeof fakeKV>): CloudflareEnv {
  const env: CloudflareEnv = {};
  if (db) env.DB = db as any;
  if (kv) env.ARTIFACTS_KV = kv as any;
  return env;
}
