import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^cloudflare:workers$/,
        replacement: fileURLToPath(new URL('./tests/stubs/cloudflare-workers.ts', import.meta.url))
      },
      {
        find: /^@\//,
        replacement: fileURLToPath(new URL('./src/', import.meta.url))
      }
    ]
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    pool: 'forks',
    isolate: true
  }
});
