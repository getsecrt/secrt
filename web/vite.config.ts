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
      include: ['src/**/*.test.{ts,tsx}'],
      setupFiles: ['src/test-setup.ts'],
      coverage: {
        provider: 'v8',
        include: ['src/**/*.{ts,tsx}'],
        exclude: [
          'src/main.tsx',
          'src/features/test/**',
          'src/components/Icons.tsx',
          'src/components/Logo.tsx',
          'src/crypto/constants.ts',
          'src/types.ts',
          'src/**/*.test.{ts,tsx}',
          'src/test-setup.ts',
        ],
        thresholds: {
          statements: 90,
          branches: 85,
          functions: 90,
          lines: 90,
        },
      },
    }
  };
});
