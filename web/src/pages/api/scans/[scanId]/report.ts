import type { APIRoute } from 'astro';
import { getCloudflareEnv } from '@/lib/cloudflare';

export const GET: APIRoute = async (context) => {
  const { params } = context;
  const { scanId } = params;

  if (!scanId) {
    return new Response(JSON.stringify({ error: 'Missing scanId' }), { status: 400 });
  }

  const env = getCloudflareEnv(context);

  if (!env?.DB) {
    return new Response(JSON.stringify({ error: 'Service unavailable: database not provisioned' }), { status: 503 });
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT * FROM scans WHERE scan_id = ?`
    ).bind(scanId).all();

    if (!results || results.length === 0) {
      return new Response(JSON.stringify({ error: 'Report not found' }), { status: 404 });
    }

    const scan: any = results[0];

    if (scan.status === 'error') {
      return new Response(JSON.stringify({ error: 'Scan execution failed', scan_id: scan.scan_id, status: 'error' }), { status: 409 });
    }

    if (scan.status !== 'done') {
      return new Response(JSON.stringify({ error: 'Scan still in progress', scan_id: scan.scan_id, status: scan.status }), { status: 202 });
    }

    let findings: any[] = [];
    if (scan.findings) {
      try {
        findings = JSON.parse(scan.findings);
      } catch {
        findings = [];
      }
    }

    return new Response(JSON.stringify({
      scan_id: scan.scan_id,
      status: 'done',
      risk_level: scan.risk_level,
      risk_score: scan.risk_score,
      layers_run: scan.layers_run ? JSON.parse(scan.layers_run) : [],
      duration_ms: scan.duration_ms || 0,
      bundle_hash: scan.bundle_hash,
      created_at: scan.created_at,
      updated_at: scan.updated_at,
      findings
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err: any) {
    console.error("Report Fetch Error:", err);
    return new Response(JSON.stringify({ error: 'Internal server error', details: err.message }), { status: 500 });
  }
};
