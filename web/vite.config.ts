/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import preact from '@preact/preset-vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiOrigin = env.SECRT_API_ORIGIN || 'http://127.0.0.1:8080';

  return {
    // Production server mounts web assets under /static; dev serves from /.
    base: mode === 'production' ? '/static/' : '/',
    plugins: [tailwindcss(), preact()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': {
          target: apiOrigin,
          changeOrigin: true
        },
        '/healthz': {
          target: apiOrigin,
          changeOrigin: true
        }
      }
    },
    build: {
      outDir: 'dist',
      emptyOutDir: true
    },
    test: {
      environment: 'happy-dom',
      include: ['src/**/*.test.ts']
    }
  };
});
