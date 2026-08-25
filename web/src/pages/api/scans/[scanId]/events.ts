import type { APIRoute } from 'astro';
import { getCloudflareEnv } from '@/lib/cloudflare';

export const POST: APIRoute = async (context) => {
  const { params, request } = context;
  const { scanId } = params;
  if (!scanId) {
    return new Response('Missing scanId', { status: 400 });
  }

  const env = getCloudflareEnv(context);

  if (!env?.DB) {
    return new Response(JSON.stringify({ error: 'Service unavailable: database not provisioned' }), { status: 503 });
  }

  try {
    const event = await request.json();

    await env.DB.prepare(
      `INSERT INTO scan_events (scan_id, type, payload, created_at) VALUES (?, ?, ?, ?)`
    ).bind(scanId, String(event.type || 'unknown'), JSON.stringify(event), new Date().toISOString()).run();

    if (event.type === 'scan_completed' && event.result) {
      const res = event.result;
      await env.DB.prepare(
        `UPDATE scans SET status = 'done', risk_level = ?, risk_score = ?, layers_run = ?, duration_ms = ?, findings = ?, updated_at = ? WHERE scan_id = ?`
      ).bind(
        res.risk_level,
        res.risk_score,
        JSON.stringify(res.layers_run || []),
        res.duration_ms || 0,
        JSON.stringify(res.findings || []),
        new Date().toISOString(),
        scanId
      ).run();
    } else if (event.type === 'scan_failed') {
      await env.DB.prepare(
        `UPDATE scans SET status = 'error', updated_at = ? WHERE scan_id = ?`
      ).bind(new Date().toISOString(), scanId).run();
    }

    return new Response(JSON.stringify({ status: 'received' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    console.error(`Error processing event for scan ${scanId}:`, err);
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
};
