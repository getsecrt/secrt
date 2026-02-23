/// <reference types="vitest/config" />
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig, loadEnv } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import preact from '@preact/preset-vite';

/** Read the workspace version from the root Cargo.toml (single source of truth). */
function readCargoVersion(): string {
  const cargoToml = readFileSync(
    resolve(__dirname, '..', 'Cargo.toml'),
    'utf-8',
  );
  const match = cargoToml.match(/^\s*version\s*=\s*"([^"]+)"/m);
  return match?.[1] ?? 'unknown';
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiOrigin = env.SECRT_API_ORIGIN || 'http://127.0.0.1:8080';
  const appVersion = readCargoVersion();

  return {
    // Production server mounts web assets under /static; dev serves from /.
    base: mode === 'production' ? '/static/' : '/',
    define: {
      'import.meta.env.VITE_APP_VERSION': JSON.stringify(appVersion),
    },
    plugins: [tailwindcss(), preact()],
    server: {
      host: 'localhost',
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
        },
        '/.well-known': {
          target: apiOrigin,
          changeOrigin: true
        }
      }
    },
    optimizeDeps: {
      exclude: ['@bokuweb/zstd-wasm'],
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
          'src/features/trust/HowItWorksPage.tsx',
          'src/components/Icons.tsx',
          'src/components/HowItWorks.tsx',
          'src/components/Layout.tsx',
          'src/components/Logo.tsx',
          'src/features/send/ShareResult.tsx',
          'src/features/send/TtlSelector.tsx',
          'src/crypto/constants.ts',
          'src/types.ts',
          'src/**/*.test.{ts,tsx}',
          'src/test-setup.ts',
        ],
        thresholds: {
          statements: 90,
          branches: 85,
          functions: 85,
          lines: 90,
        },
      },
    }
  };
});
