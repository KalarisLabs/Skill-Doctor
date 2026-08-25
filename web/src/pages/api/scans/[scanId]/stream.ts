import type { APIRoute } from 'astro';
import { getCloudflareEnv } from '@/lib/cloudflare';

export const GET: APIRoute = async (context) => {
  const { params } = context;
  const { scanId } = params;

  if (!scanId) {
    return new Response('Missing scanId', { status: 400 });
  }

  const env = getCloudflareEnv(context);

  if (!env?.DB) {
    return new Response('Service unavailable: database not provisioned', { status: 503 });
  }

  const encoder = new TextEncoder();
  let intervalId: any = null;
  let lastEventId = 0;
  let closed = false;

  const stream = new ReadableStream({
    async start(controller) {
      controller.enqueue(
        encoder.encode(`data: ${JSON.stringify({ type: 'connected', scan_id: scanId, timestamp: new Date().toISOString() })}\n\n`)
      );

      const finish = () => {
        if (closed) return;
        closed = true;
        if (intervalId) clearInterval(intervalId);
        try { controller.close(); } catch { /* already closed */ }
      };

      const tick = async () => {
        if (closed) return;
        try {
          // Replay any events persisted since the last poll
          const { results } = await env.DB.prepare(
            `SELECT id, type, payload FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id ASC LIMIT 100`
          ).bind(scanId, lastEventId).all();

          for (const row of results as any[]) {
            lastEventId = row.id;
            controller.enqueue(encoder.encode(`data: ${row.payload}\n\n`));
            if (row.type === 'scan_completed' || row.type === 'scan_failed') {
              finish();
              return;
            }
          }

          // Safety net: pipeline may have finished without a terminal event
          if (!closed && results.length === 0) {
            const { results: scanRows } = await env.DB.prepare(
              `SELECT status FROM scans WHERE scan_id = ?`
            ).bind(scanId).all();
            const scan: any = scanRows?.[0];
            if (scan?.status === 'error') {
              controller.enqueue(
                encoder.encode(`data: ${JSON.stringify({ type: 'scan_failed', scan_id: scanId, error: 'Scan execution failed.' })}\n\n`)
              );
              finish();
              return;
            }
            if (scan?.status === 'done') {
              const { results: finalEvents } = await env.DB.prepare(
                `SELECT id, type, payload FROM scan_events WHERE scan_id = ? AND type = 'scan_completed' ORDER BY id DESC LIMIT 1`
              ).bind(scanId).all();
              if (finalEvents && finalEvents.length > 0) {
                lastEventId = (finalEvents[0] as any).id;
                controller.enqueue(encoder.encode(`data: ${(finalEvents[0] as any).payload}\n\n`));
              }
              finish();
              return;
            }
          }

          if (!closed) {
            controller.enqueue(encoder.encode(`: heartbeat\n\n`));
          }
        } catch {
          finish();
        }
      };

      // Hard cap: never hold a connection open beyond 10 minutes
      setTimeout(finish, 600000);

      intervalId = setInterval(tick, 1500);
      await tick();
    },
    cancel() {
      closed = true;
      if (intervalId) clearInterval(intervalId);
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    },
  });
};
