import type { APIRoute } from 'astro';
import { getCloudflareEnv } from '@/lib/cloudflare';

export const GET: APIRoute = async (context) => {
  const { params } = context;
  const key = params.key;

  if (!key) {
    return new Response('Missing artifact key', { status: 400 });
  }

  // Enforce scan namespace security: scans/{scanId}/...
  if (!key.startsWith('scans/')) {
    return new Response('Access denied: Key outside allowed namespace', { status: 403 });
  }

  const env = getCloudflareEnv(context);

  if (!env?.ARTIFACTS_KV) {
    return new Response('Service unavailable: artifact storage not provisioned', { status: 503 });
  }

  try {
    const value = await env.ARTIFACTS_KV.get(key);
    if (value === null) {
      return new Response('Artifact not found', { status: 404 });
    }

    return new Response(value, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      },
    });
  } catch (error: any) {
    console.error('Artifact retrieval error:', error);
    return new Response('Internal error retrieving artifact', { status: 500 });
  }
};
