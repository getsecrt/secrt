/**
 * Camera-based QR decoder built on top of `qr-scanner` (Nimiq's wrapper).
 *
 * Decoded results are passed through `parsePairUrl` so accidental scans of
 * unrelated QR codes are silently ignored. Camera choice persists in
 * localStorage so users on devices with poor close-focus on the default
 * back camera don't have to re-pick every visit.
 */

import { useEffect, useRef, useState } from 'preact/hooks';
import QrScanner from 'qr-scanner';
import { parsePairUrl } from '../../lib/url';
import {
  CameraIcon,
  TriangleExclamationIcon,
  XMarkIcon,
} from '../../components/Icons';
import { CardHeading } from '../../components/CardHeading';
import { debugInfo } from '../../lib/debug-log';

interface QrScannerProps {
  /** Called once with a valid pair code; the parent should close the modal. */
  onCode: (code: string) => void;
  /** Called when the user gives up on the camera; switch to typed entry. */
  onTypeInstead: () => void;
  onClose: () => void;
}

const CAMERA_ID_KEY = 'secrt:pair:cameraId';

type ScannerState =
  | { kind: 'starting' }
  | { kind: 'running' }
  | { kind: 'permission-denied' }
  | { kind: 'no-camera' }
  | { kind: 'error'; message: string };

interface CameraInfo {
  id: string;
  label: string;
}

export function QrScannerView({
  onCode,
  onTypeInstead,
  onClose,
}: QrScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const scannerRef = useRef<QrScanner | null>(null);
  const decodedRef = useRef(false);
  const [state, setState] = useState<ScannerState>({ kind: 'starting' });
  const [cameras, setCameras] = useState<CameraInfo[]>([]);
  const [activeCameraId, setActiveCameraId] = useState<string | null>(null);

  // Boot camera + scanner on mount.
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const stored = (() => {
      try {
        return localStorage.getItem(CAMERA_ID_KEY);
      } catch {
        return null;
      }
    })();

    let cancelled = false;
    const scanner = new QrScanner(
      video,
      (result) => {
        if (decodedRef.current) return;
        debugInfo('qr-scanner', {
          event: 'decode',
          dataLen: result.data.length,
        });
        const parsed = parsePairUrl(result.data);
        if (!parsed) {
          debugInfo('qr-scanner', {
            event: 'decode-non-pair',
            sample: result.data.slice(0, 40),
          });
          return; // tolerate unrelated QR codes
        }
        decodedRef.current = true;
        onCode(parsed.code);
      },
      {
        preferredCamera: stored ?? 'environment',
        maxScansPerSecond: 5,
        highlightScanRegion: true,
        highlightCodeOutline: true,
      },
    );
    scannerRef.current = scanner;
    // Try both polarities (dark-on-light AND light-on-dark). Some capture
    // pipelines and dark-mode QR renders flip the contrast; default
    // qr-scanner only checks the original.
    scanner.setInversionMode('both');

    (async () => {
      try {
        await scanner.start();
        if (cancelled) return;
        setState({ kind: 'running' });

        try {
          const list = await QrScanner.listCameras(true);
          if (cancelled) return;
          if (list.length === 0) {
            setState({ kind: 'no-camera' });
            return;
          }
          setCameras(list.map((c) => ({ id: c.id, label: c.label })));
          if (stored && list.some((c) => c.id === stored)) {
            setActiveCameraId(stored);
          } else {
            // Fall back to the first listed camera label as our active id
            // (qr-scanner keeps preferredCamera selection internal).
            setActiveCameraId(list[0]?.id ?? null);
          }
        } catch {
          // listCameras can require permission on Firefox; we already started
          // so this is non-fatal — just hide the picker.
        }
      } catch (err) {
        if (cancelled) return;
        const has = await QrScanner.hasCamera().catch(() => false);
        if (!has) {
          setState({ kind: 'no-camera' });
          return;
        }
        const msg = err instanceof Error ? err.message : String(err);
        // Heuristic: most browsers report a NotAllowedError here.
        if (
          /denied|NotAllowed|permission/i.test(msg) ||
          (err instanceof DOMException && err.name === 'NotAllowedError')
        ) {
          setState({ kind: 'permission-denied' });
        } else {
          setState({ kind: 'error', message: msg });
        }
      }
    })();

    return () => {
      cancelled = true;
      scannerRef.current?.stop();
      scannerRef.current?.destroy();
      scannerRef.current = null;
    };
  }, [onCode]);

  const handleSelectCamera = async (id: string) => {
    const scanner = scannerRef.current;
    if (!scanner) return;
    try {
      await scanner.setCamera(id);
      setActiveCameraId(id);
      try {
        localStorage.setItem(CAMERA_ID_KEY, id);
      } catch {
        /* storage may be disabled */
      }
    } catch (err) {
      const msg =
        err instanceof Error ? err.message : 'Failed to switch camera';
      setState({ kind: 'error', message: msg });
    }
  };

  return (
    <div class="space-y-4">
      <button
        type="button"
        class="absolute top-3 right-3 rounded p-1 text-muted transition-colors hover:text-text"
        onClick={onClose}
        aria-label="Close scanner"
      >
        <XMarkIcon class="size-5" />
      </button>

      <CardHeading
        class="mb-0!"
        icon={<CameraIcon class="size-10" />}
        title="Scan QR Code"
      />

      {(state.kind === 'starting' || state.kind === 'running') && (
        <>
          <div class="overflow-hidden rounded-lg bg-black">
            <video
              ref={videoRef}
              class="aspect-square w-full object-cover"
              playsInline
              muted
            />
          </div>

          {cameras.length > 1 && (
            <div class="flex justify-center">
              <label class="flex items-center gap-2 text-sm">
                <span class="text-muted">Camera</span>
                <select
                  class="input py-1"
                  value={activeCameraId ?? ''}
                  onChange={(e) =>
                    handleSelectCamera((e.target as HTMLSelectElement).value)
                  }
                >
                  {cameras.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.label || 'Camera'}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}
        </>
      )}

      {state.kind === 'permission-denied' && (
        <div class="space-y-3 text-center">
          <div role="alert" class="alert-error flex items-center gap-2">
            <TriangleExclamationIcon class="size-5 shrink-0" />
            Camera permission was denied.
          </div>
          <button
            type="button"
            class="btn btn-primary tracking-wider uppercase"
            onClick={onTypeInstead}
          >
            Type the code instead
          </button>
        </div>
      )}

      {state.kind === 'no-camera' && (
        <div class="space-y-3 text-center">
          <p class="text-muted">No camera was found on this device.</p>
          <button
            type="button"
            class="btn btn-primary tracking-wider uppercase"
            onClick={onTypeInstead}
          >
            Type the code instead
          </button>
        </div>
      )}

      {state.kind === 'error' && (
        <div class="space-y-3">
          <div role="alert" class="alert-error flex items-center gap-2">
            <TriangleExclamationIcon class="size-5 shrink-0" />
            {state.message}
          </div>
          <button
            type="button"
            class="link mx-auto block"
            onClick={onTypeInstead}
          >
            Type the code instead
          </button>
        </div>
      )}
    </div>
  );
}
