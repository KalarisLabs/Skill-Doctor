import type { APIRoute } from 'astro';
import { getCloudflareEnv, getClientIp } from '@/lib/cloudflare';
import { executeScanPipeline } from '@/lib/scanner';

async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export const POST: APIRoute = async (context) => {
  const { request, locals } = context;
  try {
    const data = await request.json();
    const { source, layers = ['static', 'threat_intel'] } = data;

    if (!source) {
      return new Response(JSON.stringify({ error: 'Source is required' }), { status: 400 });
    }
    
    // SSRF Protection: Validate URL targets if source is a URL
    if (typeof source === 'string' && source.startsWith('http')) {
      try {
        const url = new URL(source);
        if (['localhost', '127.0.0.1', '::1', '169.254.169.254'].includes(url.hostname)) {
          return new Response(JSON.stringify({ error: 'Disallowed host by SSRF policy' }), { status: 403 });
        }
      } catch {
        return new Response(JSON.stringify({ error: 'Invalid URL format' }), { status: 400 });
      }
    }

    const scanId = crypto.randomUUID();
    const env = getCloudflareEnv(context);

    if (!env?.DB || !env?.ARTIFACTS_KV) {
      return new Response(JSON.stringify({ error: 'Service unavailable: storage bindings not provisioned' }), { status: 503 });
    }

    // Artifact storage namespace: scans/{scanId}/...
    const artifactKey = `scans/${scanId}/artifact.md`;
    const artifactSha256 = await sha256Hex(source);

    // 1. Store artifact in KV (Artifact Plane) with 72h auto-eviction
    await env.ARTIFACTS_KV.put(artifactKey, source, {
      expirationTtl: 259200, // 72 hours TTL
      metadata: {
        scanId,
        sha256: artifactSha256,
        createdAt: new Date().toISOString()
      }
    });

    // 2. Persist initial queued record in D1 (Durable Metadata Plane)
    await env.DB.prepare(
      `INSERT INTO scans (scan_id, source, status, bundle_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      scanId,
      source.length > 500 ? source.substring(0, 500) + '...' : source,
      'queued',
      artifactSha256,
      new Date().toISOString(),
      new Date().toISOString()
    ).run();

    // 3. Execute pipeline in-request
    const scanPromise = executeScanPipeline(scanId, source, artifactSha256, layers, env);
    
    // In Astro v6, Cloudflare ExecutionContext is on locals.cfContext
    const ctx = (locals as any)?.cfContext || (locals as any)?.ctx;
    if (ctx && typeof ctx.waitUntil === 'function') {
      ctx.waitUntil(scanPromise);
    }

    return new Response(JSON.stringify({
      scanId,
      status: 'queued',
      artifact: {
        key: artifactKey,
        sha256: artifactSha256
      }
    }), {
      status: 202,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error: any) {
    console.error('Scan Creation Error:', error);
    return new Response(JSON.stringify({ error: 'Internal server error', details: error.message }), { status: 500 });
  }
};
