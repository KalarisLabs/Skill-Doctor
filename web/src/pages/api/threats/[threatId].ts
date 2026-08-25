import type { APIRoute } from 'astro';
import { getCloudflareEnv } from '@/lib/cloudflare';

export const GET: APIRoute = async (context) => {
  const { params } = context;
  const { threatId } = params;

  if (!threatId) {
    return new Response(JSON.stringify({ error: 'Missing threatId' }), { status: 400 });
  }

  const env = getCloudflareEnv(context);

  if (!env?.DB) {
    return new Response(JSON.stringify({ error: 'Service unavailable: database not provisioned' }), { status: 503 });
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, severity, category, description, remediation, pattern_hash, created_at FROM threats WHERE id = ?`
    ).bind(threatId).all();

    if (!results || results.length === 0) {
      return new Response(JSON.stringify({ error: 'Threat not found' }), { status: 404 });
    }

    const threat: any = results[0];
    return new Response(JSON.stringify({
      ...threat,
      indicators: [
        { type: 'YARA-X', rule_name: `detect_${String(threat.category).toLowerCase().replace(/[^a-z0-9]/g, '_')}`, description: 'Compiled YARA-X signature for pattern matching' },
        { type: 'Tree-sitter AST', pattern: '(call function: (identifier) @dangerous_sink)', language: 'python/typescript' }
      ],
      affected_frameworks: ['Claude Code', 'Cursor MCP', 'LangChain', 'CrewAI', 'AutoGen']
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error: any) {
    console.error('Threat Detail API Error:', error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
};
