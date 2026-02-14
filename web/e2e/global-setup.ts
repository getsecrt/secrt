import { execSync, spawn, type ChildProcess } from 'node:child_process';
import { writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');
const WEB_DIR = join(ROOT, 'web');

const API_PORT = Number(process.env.SECRT_E2E_API_PORT ?? 3199);
const VITE_PORT = Number(process.env.SECRT_E2E_PORT ?? 5199);
const DB_NAME = process.env.SECRT_E2E_DB ?? 'secrt_e2e';
const DB_USER =
  process.env.SECRT_E2E_DB_USER ?? process.env.USER ?? 'postgres';
const DB_HOST = process.env.SECRT_E2E_DB_HOST ?? '127.0.0.1';
const DB_PORT = process.env.SECRT_E2E_DB_PORT ?? '5432';

const PID_FILE = join(WEB_DIR, '.e2e-server.pid');
const VITE_PID_FILE = join(WEB_DIR, '.e2e-vite.pid');

function waitForServer(url: string, timeoutMs = 30_000): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      fetch(url)
        .then((res) => {
          if (res.ok) resolve();
          else retry();
        })
        .catch(retry);
    };
    const retry = () => {
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Server did not start within ${timeoutMs}ms`));
        return;
      }
      setTimeout(check, 250);
    };
    check();
  });
}

export default async function globalSetup() {
  // 1. Build the server
  console.log('[e2e] Building server...');
  execSync('cargo build -p secrt-server', { cwd: ROOT, stdio: 'inherit' });

  // 2. Ensure test database exists
  console.log(`[e2e] Ensuring database '${DB_NAME}' exists...`);
  try {
    execSync(
      `psql -U ${DB_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || psql -U ${DB_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres -c "CREATE DATABASE ${DB_NAME}"`,
      { stdio: 'inherit' },
    );
  } catch {
    console.warn(
      '[e2e] Could not create database — assuming it already exists',
    );
  }

  const DATABASE_URL = `postgres://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}`;
  const serverBin = join(ROOT, 'target', 'debug', 'secrt-server');

  if (!existsSync(serverBin)) {
    throw new Error(`Server binary not found at ${serverBin}`);
  }

  // 3. Start the Rust API server
  console.log(`[e2e] Starting API server on port ${API_PORT}...`);
  const server: ChildProcess = spawn(serverBin, [], {
    env: {
      ...process.env,
      ENV: 'development',
      LISTEN_ADDR: `127.0.0.1:${API_PORT}`,
      PUBLIC_BASE_URL: `http://127.0.0.1:${VITE_PORT}`,
      DATABASE_URL,
      RUST_LOG: 'warn',
      // Relax rate limits for E2E testing
      PUBLIC_CREATE_RATE: '10',
      PUBLIC_CREATE_BURST: '50',
      CLAIM_RATE: '10',
      CLAIM_BURST: '50',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });

  server.stderr?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log(`[api] ${line}`);
  });

  server.on('error', (err) => {
    console.error('[e2e] Failed to start API server:', err);
  });

  if (server.pid) {
    writeFileSync(PID_FILE, String(server.pid), 'utf-8');
  }

  await waitForServer(`http://127.0.0.1:${API_PORT}/healthz`);
  console.log('[e2e] API server is ready.');

  // 4. Start Vite dev server (proxies /api to the Rust server)
  console.log(`[e2e] Starting Vite dev server on port ${VITE_PORT}...`);
  const vite: ChildProcess = spawn(
    'pnpm',
    [
      'exec',
      'vite',
      '--host',
      '127.0.0.1',
      '--port',
      String(VITE_PORT),
      '--strictPort',
    ],
    {
      cwd: WEB_DIR,
      env: {
        ...process.env,
        SECRT_API_ORIGIN: `http://127.0.0.1:${API_PORT}`,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    },
  );

  vite.stdout?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log(`[vite] ${line}`);
  });

  vite.stderr?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log(`[vite] ${line}`);
  });

  if (vite.pid) {
    writeFileSync(VITE_PID_FILE, String(vite.pid), 'utf-8');
  }

  await waitForServer(`http://127.0.0.1:${VITE_PORT}/`);
  console.log('[e2e] Vite dev server is ready.');
}
