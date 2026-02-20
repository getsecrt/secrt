import { useState, useEffect, useCallback } from 'preact/hooks';
import { AuthGuard } from '../../components/AuthGuard';
import { useAuth } from '../../lib/auth-context';
import {
  listApiKeys,
  revokeApiKey,
  registerApiKey,
  deleteAccount,
  upsertAmkWrapper,
  fetchInfo,
  updateDisplayName,
  listPasskeys,
  revokePasskey,
  renamePasskey,
  addPasskeyStart,
  addPasskeyFinish,
} from '../../lib/api';
import { generateApiKeyMaterial, formatWireApiKey } from '../../crypto/apikey';
import {
  generateAmk,
  computeAmkCommit,
  deriveAmkWrapKey,
  buildWrapAad,
  wrapAmk,
} from '../../crypto/amk';
import { base64urlEncode } from '../../crypto/encoding';
import { storeAmk, loadAmk, clearAmk } from '../../lib/amk-store';
import {
  TrashIcon,
  ClipboardIcon,
  SquarePlusIcon,
  CircleXmarkIcon,
  PasskeyIcon,
  UserIcon,
  XMarkIcon,
} from '../../components/Icons';
import { SyncNotesKeyButton } from '../../components/SyncNotesKeyButton';
import { CardHeading } from '../../components/CardHeading';
import { Modal } from '../../components/Modal';
import { navigate } from '../../router';
import type { ApiKeyItem, PasskeyItem } from '../../types';
import {
  createPasskeyCredential,
  supportsWebAuthn,
  generateUserId,
} from '../../lib/webauthn';

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function ApiKeysCard() {
  const auth = useAuth();
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);

  const fetchKeys = useCallback(async () => {
    if (!auth.sessionToken) return;
    setLoading(true);
    setError(null);
    try {
      const res = await listApiKeys(auth.sessionToken);
      setKeys(res.api_keys);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load API keys');
    } finally {
      setLoading(false);
    }
  }, [auth.sessionToken]);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  const handleCreate = useCallback(async () => {
    if (!auth.sessionToken || !auth.userId) return;
    setCreating(true);
    setError(null);
    setNewKey(null);
    try {
      const material = await generateApiKeyMaterial();
      const { prefix } = await registerApiKey(
        auth.sessionToken,
        material.authTokenB64,
      );
      const wireKey = formatWireApiKey(prefix, material.authToken);
      setNewKey(wireKey);

      // Bootstrap AMK: generate or load existing
      try {
        const info = await fetchInfo();
        if (info.features?.encrypted_notes) {
          let amk = await loadAmk(auth.userId);
          if (!amk) {
            amk = generateAmk();
            await storeAmk(auth.userId, amk);
          }
          const commit = await computeAmkCommit(amk);
          const wrapKey = await deriveAmkWrapKey(material.rootKey);
          const aad = buildWrapAad(auth.userId, prefix, 1);
          const wrapped = await wrapAmk(amk, wrapKey, aad);
          try {
            await upsertAmkWrapper(auth.sessionToken, {
              key_prefix: prefix,
              wrapped_amk: wrapped.ct,
              nonce: wrapped.nonce,
              amk_commit: base64urlEncode(commit),
              version: wrapped.version,
            });
          } catch (wrapErr) {
            // 409 = commit mismatch, another device committed a different AMK
            const msg = wrapErr instanceof Error ? wrapErr.message : '';
            if (msg.includes('409') || msg.includes('mismatch')) {
              await clearAmk(auth.userId);
            }
            // Non-fatal: key was created, wrapper upload failed
          }
        }
      } catch {
        // Non-fatal: AMK bootstrap failed but API key still works
      }

      await fetchKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create API key');
    } finally {
      setCreating(false);
    }
  }, [auth.sessionToken, auth.userId, fetchKeys]);

  const handleRevoke = useCallback(
    async (prefix: string) => {
      if (!auth.sessionToken) return;
      setRevoking(prefix);
      setError(null);
      try {
        await revokeApiKey(auth.sessionToken, prefix);
        await fetchKeys();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Failed to revoke API key',
        );
      } finally {
        setRevoking(null);
      }
    },
    [auth.sessionToken, fetchKeys],
  );

  const handleCopy = useCallback(async () => {
    if (!newKey) return;
    try {
      await navigator.clipboard.writeText(newKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard may not be available */
    }
  }, [newKey]);

  return (
    <div class="card mb-4">
      <div class="mb-4">
        <CardHeading
          title="API Keys"
          subtitle="Use API keys with the secrt CLI or custom applications."
        />

        <div class="flex justify-center">
          <button
            type="button"
            class="btn btn-primary btn-sm tracking-wider uppercase"
            disabled={creating}
            onClick={handleCreate}
          >
            <SquarePlusIcon class="size-4" />
            {creating ? 'Creating...' : 'Create Key'}
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" class="alert-error mb-4">
          {error}
        </div>
      )}

      {newKey && (
        <div class="mb-6 rounded-lg border border-green-600/30 bg-green-50 p-6 text-center dark:border-green-400/20 dark:bg-green-950">
          <h3 class="mb-2 text-center font-semibold text-green-800 dark:text-green-200">
            API Key Created
          </h3>
          <p class="mb-3 text-center text-sm text-green-700 dark:text-green-300">
            Save this key now &mdash; it won't be shown again.
          </p>
          <code class="code block break-all">{newKey}</code>
          <button
            type="button"
            class="btn btn-primary btn-sm mt-2 w-24 tracking-wider uppercase"
            onClick={handleCopy}
          >
            <ClipboardIcon class="size-3.5" />
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      )}

      {loading && keys.length === 0 ? (
        <p class="text-muted">Loading...</p>
      ) : keys.length === 0 ? (
        <p class="text-center text-muted">No API keys yet.</p>
      ) : (
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="border-b border-border text-left text-muted">
                <th class="pr-3 pb-2 font-medium">Prefix</th>
                <th class="pr-3 pb-2 font-medium">Created</th>
                <th class="pr-3 pb-2 font-medium">Status</th>
                <th class="pb-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.prefix} class="border-b border-border/50">
                  <td class="py-2 pr-3 font-mono text-xs">{k.prefix}</td>
                  <td class="py-2 pr-3 whitespace-nowrap">
                    {formatDate(k.created_at)}
                  </td>
                  <td class="py-2 pr-3">
                    {k.revoked_at ? (
                      <span class="rounded-full bg-red-100 px-2 py-0.5 text-xs text-red-700 dark:bg-red-900/30 dark:text-red-400">
                        Revoked
                      </span>
                    ) : (
                      <span class="rounded-full bg-green-100 px-2 py-0.5 text-xs text-green-700 dark:bg-green-900/30 dark:text-green-400">
                        Active
                      </span>
                    )}
                  </td>
                  <td class="py-2 text-right">
                    {!k.revoked_at && (
                      <button
                        type="button"
                        class="btn-destructive-subtle"
                        disabled={revoking === k.prefix}
                        onClick={() => handleRevoke(k.prefix)}
                      >
                        <CircleXmarkIcon class="size-4 text-error" />
                        {revoking === k.prefix ? 'Revoking...' : 'Revoke'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function passkeyLabel(pk: PasskeyItem): string {
  return pk.label || 'Default';
}

function PasskeysCard() {
  const auth = useAuth();
  const [passkeys, setPasskeys] = useState<PasskeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [revokingId, setRevokingId] = useState<number | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalPasskey, setModalPasskey] = useState<PasskeyItem | null>(null);
  const [modalLabel, setModalLabel] = useState('');
  const [savingLabel, setSavingLabel] = useState(false);

  const fetchPasskeys = useCallback(async (): Promise<PasskeyItem[]> => {
    if (!auth.sessionToken) return [];
    setLoading(true);
    setError(null);
    try {
      const res = await listPasskeys(auth.sessionToken);
      setPasskeys(res.passkeys);
      return res.passkeys;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load passkeys');
      return [];
    } finally {
      setLoading(false);
    }
  }, [auth.sessionToken]);

  useEffect(() => {
    fetchPasskeys();
  }, [fetchPasskeys]);

  const openRenameModal = useCallback((pk: PasskeyItem) => {
    setModalPasskey(pk);
    setModalLabel(pk.label);
    setModalOpen(true);
  }, []);

  const closeModal = useCallback(() => {
    setModalOpen(false);
    setSavingLabel(false);
  }, []);

  const handleSaveLabel = useCallback(
    async (e: Event) => {
      e.preventDefault();
      if (!auth.sessionToken || !modalPasskey) return;
      const trimmed = modalLabel.trim();
      setSavingLabel(true);
      setError(null);
      try {
        await renamePasskey(auth.sessionToken, modalPasskey.id, trimmed);
        setPasskeys((prev) =>
          prev.map((p) =>
            p.id === modalPasskey.id ? { ...p, label: trimmed } : p,
          ),
        );
        closeModal();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Failed to rename passkey',
        );
        setSavingLabel(false);
      }
    },
    [auth.sessionToken, modalPasskey, modalLabel, closeModal],
  );

  const handleAdd = useCallback(async () => {
    if (!auth.sessionToken || !supportsWebAuthn()) return;
    setAdding(true);
    setError(null);
    try {
      const { challenge_id, challenge } = await addPasskeyStart(
        auth.sessionToken,
      );
      const userId = generateUserId();
      const reg = await createPasskeyCredential(
        challenge,
        userId,
        auth.displayName ?? 'User',
        auth.displayName ?? 'User',
      );
      await addPasskeyFinish(auth.sessionToken, {
        challenge_id,
        credential_id: reg.credentialId,
        public_key: reg.publicKey,
      });
      const updated = await fetchPasskeys();
      // Open rename modal for the newly added passkey (highest id)
      if (updated.length > 0) {
        const newest = updated.reduce((a, b) => (a.id > b.id ? a : b));
        openRenameModal(newest);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to add passkey';
      if (!msg.includes('cancelled') && !msg.includes('AbortError')) {
        setError(msg);
      }
    } finally {
      setAdding(false);
    }
  }, [auth.sessionToken, auth.displayName, fetchPasskeys, openRenameModal]);

  const handleRevoke = useCallback(
    async (id: number) => {
      if (!auth.sessionToken) return;
      setRevokingId(id);
      setError(null);
      try {
        await revokePasskey(auth.sessionToken, id);
        await fetchPasskeys();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Failed to revoke passkey',
        );
      } finally {
        setRevokingId(null);
      }
    },
    [auth.sessionToken, fetchPasskeys],
  );

  return (
    <div class="card mb-4">
      <div class="mb-4">
        <CardHeading
          title="Passkeys"
          subtitle="Manage the passkeys used to sign in to your account."
        />

        {supportsWebAuthn() && (
          <div class="flex justify-center">
            <button
              type="button"
              class="btn btn-primary btn-sm tracking-wider uppercase"
              disabled={adding}
              onClick={handleAdd}
            >
              <SquarePlusIcon class="size-4" />
              {adding ? 'Adding...' : 'Add Passkey'}
            </button>
          </div>
        )}
      </div>

      {error && (
        <div role="alert" class="alert-error mb-4">
          {error}
        </div>
      )}

      {loading && passkeys.length === 0 ? (
        <p class="text-muted">Loading...</p>
      ) : passkeys.length === 0 ? (
        <p class="text-center text-muted">No passkeys.</p>
      ) : (
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="border-b border-border text-left text-muted">
                <th class="pr-3 pb-2 font-medium">Label</th>
                <th class="pr-3 pb-2 font-medium">Created</th>
                <th class="pb-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {passkeys.map((pk) => (
                <tr key={pk.id} class="border-b border-border/50">
                  <td class="py-2 pr-3">
                    <button
                      type="button"
                      class="hover:text-primary ml-1 inline-flex items-center gap-1.5 text-left transition-colors"
                      title="Click to rename"
                      onClick={() => openRenameModal(pk)}
                    >
                      <PasskeyIcon class="size-4 shrink-0 text-muted" />
                      <span>{passkeyLabel(pk)}</span>
                    </button>
                  </td>
                  <td class="py-2 pr-3 whitespace-nowrap">
                    {formatDate(pk.created_at)}
                  </td>
                  <td class="py-2 text-right">
                    {passkeys.length > 1 && (
                      <button
                        type="button"
                        class="btn-destructive-subtle"
                        disabled={revokingId === pk.id}
                        title="Revoke passkey"
                        onClick={() => handleRevoke(pk.id)}
                      >
                        <CircleXmarkIcon class="size-4 text-error" />
                        {revokingId === pk.id ? 'Revoking...' : 'Revoke'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Rename passkey modal */}
      <Modal
        open={modalOpen}
        onClose={closeModal}
        dismissible
        asForm
        onSubmit={handleSaveLabel}
        aria-label="Rename passkey"
      >
        <button
          type="button"
          class="absolute top-3 right-3 rounded p-1 text-muted transition-colors hover:text-text"
          onClick={closeModal}
          aria-label="Close"
        >
          <XMarkIcon class="size-5" />
        </button>

        <CardHeading
          icon={<PasskeyIcon class="size-10" />}
          title={modalPasskey?.label ? 'Rename Passkey' : 'Name Passkey'}
          subtitle={
            modalPasskey ? `Created ${formatDate(modalPasskey.created_at)}` : ''
          }
        />

        <div class="space-y-1">
          <label class="label" for="passkey-label">
            <PasskeyIcon class="size-4 opacity-60" aria-hidden="true" />
            Label
          </label>
          <input
            id="passkey-label"
            type="text"
            class="input"
            value={modalLabel}
            maxLength={100}
            placeholder="e.g. MacBook, iPhone, Work laptop"
            onInput={(e) => setModalLabel((e.target as HTMLInputElement).value)}
            autofocus
            autocomplete="off"
          />
          <p class="text-center text-sm text-muted">
            A friendly name to identify this passkey
          </p>
        </div>

        <button
          type="submit"
          class="btn btn-primary w-full tracking-wider uppercase"
          disabled={savingLabel}
        >
          {savingLabel ? 'Saving\u2026' : 'Save'}
        </button>
      </Modal>
    </div>
  );
}

function AccountCard() {
  const auth = useAuth();
  const [confirmText, setConfirmText] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);
  const [nameInput, setNameInput] = useState(auth.displayName ?? '');
  const [saving, setSaving] = useState(false);

  const nameChanged =
    nameInput.trim() !== '' && nameInput.trim() !== (auth.displayName ?? '');

  const handleSaveName = useCallback(async () => {
    if (!auth.sessionToken) return;
    const trimmed = nameInput.trim();
    if (!trimmed || trimmed.length > 100) return;
    setSaving(true);
    setError(null);
    try {
      const res = await updateDisplayName(auth.sessionToken, trimmed);
      auth.setDisplayName(res.display_name);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update name');
    } finally {
      setSaving(false);
    }
  }, [auth, nameInput]);

  const handleDelete = useCallback(async () => {
    if (!auth.sessionToken || confirmText !== 'DELETE') return;
    setDeleting(true);
    setError(null);
    try {
      await deleteAccount(auth.sessionToken);
      await auth.logout();
      navigate('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete account');
      setDeleting(false);
    }
  }, [auth, confirmText]);

  return (
    <div class="card space-y-6">
      <CardHeading
        title="Your Account"
        subtitle="Manage your display name and account."
      />

      <div class="space-y-1">
        <label class="label" for="display-name">
          <UserIcon class="size-4 opacity-60" aria-hidden="true" />
          Change Display Name
        </label>
        <div class="relative">
          <input
            id="display-name"
            type="text"
            class="input"
            value={nameInput}
            maxLength={100}
            onInput={(e) => setNameInput((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && nameChanged) handleSaveName();
            }}
            autocomplete="off"
          />
        </div>
        <p class="mt-3 text-center text-sm text-muted">
          {nameChanged ? (
            <button
              type="button"
              class="btn btn-primary btn-sm tracking-wider uppercase"
              disabled={saving}
              onClick={handleSaveName}
            >
              {saving ? 'Saving\u2026' : 'Update Name'}
            </button>
          ) : (
            <button
              type="button"
              class="btn btn-sm invisible"
              disabled={saving}
              onClick={handleSaveName}
            >
              &nbsp;
            </button>
          )}
        </p>
      </div>

      {error && (
        <div role="alert" class="alert-error">
          {error}
        </div>
      )}

      {!showConfirm ? (
        <div class="mt-16 flex justify-center">
          <button
            type="button"
            class="btn btn-sm btn-danger inline-flex tracking-wider uppercase"
            onClick={() => setShowConfirm(true)}
          >
            <TrashIcon class="size-3.5" />
            Delete Account
          </button>
        </div>
      ) : (
        <div class="rounded-md border border-red-300 bg-red-50 p-3 dark:border-red-700 dark:bg-red-900/20">
          <h3 class="mb-2 text-center font-semibold text-red-700 dark:text-red-400">
            Really Delete Your Account?
          </h3>
          <p class="mb-2 text-red-700 dark:text-red-400">
            This will permanently delete your account, burn all secrets, and
            revoke all API keys.
          </p>
          <p class="mb-2 text-red-700 dark:text-red-400">
            Type <strong>DELETE</strong> to confirm.
          </p>
          <div class="flex items-center gap-2">
            <input
              type="text"
              class="input flex-1 border-red-300 dark:border-red-700"
              placeholder="Type DELETE"
              value={confirmText}
              onInput={(e) =>
                setConfirmText((e.target as HTMLInputElement).value)
              }
            />
            <button
              type="button"
              class="btn btn-danger tracking-wider uppercase"
              disabled={confirmText !== 'DELETE' || deleting}
              onClick={handleDelete}
            >
              {deleting ? 'Deleting...' : 'Delete'}
            </button>
            <button
              type="button"
              class="btn tracking-wider uppercase"
              onClick={() => {
                setShowConfirm(false);
                setConfirmText('');
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function SettingsContent() {
  return (
    <div class="space-y-4">
      <div class="card">
        <CardHeading
          title="Notes Key"
          subtitle="Allow your encrypted notes to be viewed on another browser or device."
          class="mb-3"
        />
        <div class="text-center">
          <SyncNotesKeyButton />
        </div>
      </div>
      <ApiKeysCard />
      <PasskeysCard />
      <AccountCard />
    </div>
  );
}

export function SettingsPage() {
  return (
    <AuthGuard>
      <SettingsContent />
    </AuthGuard>
  );
}
