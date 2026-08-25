import type { APIRoute } from 'astro';
import { getCloudflareEnv } from '@/lib/cloudflare';

export const GET: APIRoute = async (context) => {
  const env = getCloudflareEnv(context);

  if (!env?.DB) {
    return new Response(JSON.stringify({ error: 'Service unavailable: database not provisioned' }), { status: 503 });
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT scan_id, source, status, bundle_hash, risk_level, risk_score, layers_run, duration_ms, created_at, updated_at FROM scans ORDER BY created_at DESC LIMIT 50`
    ).all();

    return new Response(JSON.stringify(results || []), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error: any) {
    console.error('Scan History API Error:', error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
};
