import { readFileSync, unlinkSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PID_FILE = join(__dirname, '..', '.e2e-server.pid');
const VITE_PID_FILE = join(__dirname, '..', '.e2e-vite.pid');

function killPid(pidFile: string, label: string) {
  if (!existsSync(pidFile)) {
    console.log(`[e2e] No PID file for ${label} — may not have started.`);
    return;
  }

  const pid = Number(readFileSync(pidFile, 'utf-8').trim());
  console.log(`[e2e] Stopping ${label} (PID ${pid})...`);

  try {
    process.kill(pid, 'SIGTERM');
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'ESRCH') {
      console.warn(`[e2e] Error stopping ${label}:`, err);
    }
  }

  try {
    unlinkSync(pidFile);
  } catch {
    // ignore
  }
}

export default async function globalTeardown() {
  killPid(VITE_PID_FILE, 'Vite dev server');
  killPid(PID_FILE, 'API server');

  // Give processes time to shut down
  await new Promise((resolve) => setTimeout(resolve, 500));
  console.log('[e2e] All servers stopped.');
}
