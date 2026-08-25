import type { APIRoute } from 'astro';
import { getCloudflareEnv } from '@/lib/cloudflare';

export const GET: APIRoute = async (context) => {
  const env = getCloudflareEnv(context);

  if (!env?.DB) {
    return new Response(JSON.stringify({ error: 'Service unavailable: database not provisioned' }), { status: 503 });
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, severity, category, description, remediation, pattern_hash, created_at FROM threats ORDER BY severity DESC, id ASC`
    ).all();

    return new Response(JSON.stringify(results || []), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error: any) {
    console.error('Threats API Error:', error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
};
