import { useState, useEffect } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import { deviceApprove, getDeviceChallenge } from '../../lib/api';
import { loadAmk } from '../../lib/amk-store';
import {
  generateEcdhKeyPair,
  exportPublicKey,
  performEcdh,
  deriveTransferKey,
  computeSas,
} from '../../crypto/amk';
import { base64urlEncode, base64urlDecode } from '../../crypto/encoding';
import {
  CheckCircleIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { CardHeading } from '../../components/CardHeading';

type AmkTransferData = { ct: string; nonce: string; ecdh_public_key: string };

type DeviceState =
  | { step: 'confirm'; code: string }
  | { step: 'computing' }
  | { step: 'verify-sas'; code: string; sasCode: string; amkTransfer: AmkTransferData }
  | { step: 'approving' }
  | { step: 'done'; sasCode?: string }
  | { step: 'error'; message: string }
  | { step: 'no-code' };

function parseUserCode(): string | null {
  const params = new URLSearchParams(window.location.search);
  return params.get('code');
}

export function DevicePage() {
  const auth = useAuth();
  const [state, setState] = useState<DeviceState>(() => {
    const code = parseUserCode();
    return code ? { step: 'confirm', code } : { step: 'no-code' };
  });

  const userCode = state.step === 'confirm' ? state.code
    : state.step === 'verify-sas' ? state.code
    : '';

  // Redirect to login if not authenticated (preserve redirect back)
  useEffect(() => {
    if (!auth.loading && !auth.authenticated) {
      const returnUrl = `/device${window.location.search}`;
      navigate(`/login?redirect=${encodeURIComponent(returnUrl)}`);
    }
  }, [auth.loading, auth.authenticated]);

  if (auth.loading) {
    return (
      <div class="card text-center">
        <p class="text-muted">Loading...</p>
      </div>
    );
  }

  if (!auth.authenticated) {
    return null;
  }

  if (state.step === 'no-code') {
    return (
      <div class="card space-y-4 text-center">
        <TriangleExclamationIcon class="text-warning mx-auto size-8" />
        <h2 class="label">Missing Device Code</h2>
        <p class="text-muted">
          No device code found. Please use the link shown in your terminal.
        </p>
      </div>
    );
  }

  if (state.step === 'done') {
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="Device Authorized"
          icon={<CheckCircleIcon class="size-10 text-success" />}
        />

        <p class="text-muted">
          Authentication should complete momentarily.
        </p>

        {state.sasCode && (
          <div class="mt-2">
            <p class="text-muted text-sm">
              If your terminal shows a security code, verify it matches:
            </p>
            <div class="font-mono text-xl font-bold tracking-[0.2em]">
              {state.sasCode}
            </div>
          </div>
        )}
      </div>
    );
  }

  // Step 1: User clicks "Approve" — compute ECDH, then either show SAS or approve directly
  const handleApprove = async () => {
    if (!auth.sessionToken) return;
    const code = userCode;
    setState({ step: 'computing' });

    try {
      let amkTransfer: AmkTransferData | undefined;
      let computedSas: string | null = null;

      try {
        const challenge = await getDeviceChallenge(auth.sessionToken, code);

        if (challenge.ecdh_public_key && auth.userId) {
          const amk = await loadAmk(auth.userId);

          if (amk && challenge.ecdh_public_key) {
            const browserKp = await generateEcdhKeyPair();
            const browserPkBytes = await exportPublicKey(browserKp.publicKey);

            const cliPkBytes = base64urlDecode(challenge.ecdh_public_key);
            const sharedSecret = await performEcdh(browserKp.privateKey, cliPkBytes);

            const transferKey = await deriveTransferKey(sharedSecret);
            const sas = await computeSas(sharedSecret, cliPkBytes, browserPkBytes);
            computedSas = String(sas).padStart(6, '0');

            const nonce = new Uint8Array(12);
            crypto.getRandomValues(nonce);
            const aad = new TextEncoder().encode('secrt-amk-transfer-v1');
            const tkBuf = new ArrayBuffer(transferKey.byteLength);
            new Uint8Array(tkBuf).set(transferKey);
            const nonceBuf = new ArrayBuffer(nonce.byteLength);
            new Uint8Array(nonceBuf).set(nonce);
            const aadBuf = new ArrayBuffer(aad.byteLength);
            new Uint8Array(aadBuf).set(aad);
            const amkBuf = new ArrayBuffer(amk.byteLength);
            new Uint8Array(amkBuf).set(amk);
            const cryptoKey = await crypto.subtle.importKey(
              'raw', tkBuf, 'AES-GCM', false, ['encrypt'],
            );
            const ct = await crypto.subtle.encrypt(
              { name: 'AES-GCM', iv: nonceBuf, additionalData: aadBuf },
              cryptoKey,
              amkBuf,
            );

            amkTransfer = {
              ct: base64urlEncode(new Uint8Array(ct)),
              nonce: base64urlEncode(nonce),
              ecdh_public_key: base64urlEncode(browserPkBytes),
            };
          }
        }
      } catch {
        // ECDH setup failure is non-fatal — approve without AMK transfer
      }

      // If we have a SAS code, pause for user verification before sending approval
      if (computedSas && amkTransfer) {
        setState({ step: 'verify-sas', code, sasCode: computedSas, amkTransfer });
        return;
      }

      // No AMK transfer — approve immediately
      setState({ step: 'approving' });
      await deviceApprove(auth.sessionToken, code);
      setState({ step: 'done' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Approval failed.';
      setState({ step: 'error', message });
    }
  };

  // Step 2a: User confirms SAS — send approval with AMK transfer
  const handleConfirmSas = async () => {
    if (state.step !== 'verify-sas' || !auth.sessionToken) return;
    const { sasCode, amkTransfer } = state;
    const code = state.code;
    setState({ step: 'approving' });

    try {
      await deviceApprove(auth.sessionToken, code, amkTransfer);
      setState({ step: 'done', sasCode });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Approval failed.';
      setState({ step: 'error', message });
    }
  };

  // Step 2b: User rejects SAS — approve without AMK transfer
  const handleSkipTransfer = async () => {
    if (state.step !== 'verify-sas' || !auth.sessionToken) return;
    const code = state.code;
    setState({ step: 'approving' });

    try {
      await deviceApprove(auth.sessionToken, code);
      setState({ step: 'done' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Approval failed.';
      setState({ step: 'error', message });
    }
  };

  const handleCancel = () => {
    navigate('/');
  };

  // SAS verification screen
  if (state.step === 'verify-sas') {
    return (
      <div class="card text-center">
        <CardHeading
          title="Verify Security Code"
          subtitle="A notes encryption key will be transferred to the CLI."
          class="mb-4"
        />

        <div class="my-6 space-y-4">
          <p class="text-muted text-sm">
            After confirming, verify this code matches the one shown in your terminal.
          </p>

          <div class="bg-surface-alt mx-auto rounded-lg px-6 py-4 font-mono text-3xl font-bold tracking-[0.3em]">
            {state.sasCode}
          </div>
        </div>

        <div class="flex gap-3">
          <button
            type="button"
            class="btn flex-1 tracking-wider uppercase"
            onClick={handleSkipTransfer}
          >
            Skip Transfer
          </button>
          <button
            type="button"
            class="btn btn-primary flex-1 tracking-wider uppercase"
            onClick={handleConfirmSas}
          >
            Confirm &amp; Approve
          </button>
        </div>
      </div>
    );
  }

  const busy = state.step === 'approving' || state.step === 'computing';

  return (
    <div class="card text-center">
      <CardHeading
        title="Authorize Device"
        subtitle="A CLI session is requesting access to your account."
        class="mb-4"
      />

      <div class="my-6">
        <p>Confirm this code is shown in your terminal:</p>

        <div class="bg-surface-alt mx-auto rounded-lg px-6 py-4 font-mono text-3xl font-bold tracking-[0.3em]">
          {userCode}
        </div>

        {state.step === 'error' && (
          <div
            role="alert"
            class="alert-error flex items-center gap-2 text-left"
          >
            <TriangleExclamationIcon class="size-5 shrink-0" />
            {state.message}
          </div>
        )}
      </div>

      <div class="flex gap-3">
        <button
          type="button"
          class="btn flex-1 tracking-wider uppercase"
          onClick={handleCancel}
          disabled={busy}
        >
          Cancel
        </button>
        <button
          type="button"
          class="btn btn-primary flex-1 tracking-wider uppercase"
          onClick={handleApprove}
          disabled={busy}
        >
          {busy ? 'Authorizing\u2026' : 'Approve'}
        </button>
      </div>
    </div>
  );
}
