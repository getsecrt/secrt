import type { SealResult, OpenResult, PayloadMeta, EnvelopeJson } from '../types';
import { base64urlEncode, base64urlDecode } from './encoding';

/** Dynamically import Tauri's invoke to avoid bundling issues in browser builds. */
async function invoke<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
  return tauriInvoke<T>(cmd, args);
}

export async function nativeSeal(
  content: Uint8Array,
  meta: PayloadMeta,
  passphrase?: string,
): Promise<SealResult> {
  const res = await invoke<{
    envelope: EnvelopeJson;
    url_key: string;
    claim_hash: string;
  }>('seal_secret', {
    contentB64: base64urlEncode(content),
    payloadType: meta.type,
    filename: meta.filename ?? null,
    mime: meta.mime ?? null,
    passphrase: passphrase ?? null,
  });
  return {
    envelope: res.envelope,
    urlKey: base64urlDecode(res.url_key),
    claimHash: res.claim_hash,
  };
}

export async function nativeOpen(
  envelope: EnvelopeJson,
  urlKey: Uint8Array,
  passphrase?: string,
): Promise<OpenResult> {
  const res = await invoke<{
    content: string;
    payload_type: string;
    filename: string | null;
    mime: string | null;
  }>('open_secret', {
    envelope,
    urlKeyB64: base64urlEncode(urlKey),
    passphrase: passphrase ?? null,
  });
  return {
    content: base64urlDecode(res.content),
    meta: {
      type: res.payload_type as 'text' | 'file' | 'binary',
      filename: res.filename ?? undefined,
      mime: res.mime ?? undefined,
    },
  };
}

export async function nativeDeriveClaimToken(
  urlKey: Uint8Array,
): Promise<Uint8Array> {
  const res = await invoke<string>('derive_claim_token', {
    urlKeyB64: base64urlEncode(urlKey),
  });
  return base64urlDecode(res);
}
