import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const callOrder: string[] = [];

vi.mock('../../crypto/amk', async () => {
  const real =
    await vi.importActual<typeof import('../../crypto/amk')>(
      '../../crypto/amk',
    );
  return {
    ...real,
    computeAmkCommit: vi.fn(async (amk: Uint8Array) => {
      callOrder.push(`computeAmkCommit(${amk.byteLength})`);
      return amk;
    }),
  };
});

vi.mock('../../lib/api', () => ({
  commitAmk: vi.fn(async () => {
    callOrder.push('commitAmk');
    return { ok: true };
  }),
}));

vi.mock('../../lib/amk-store', () => ({
  storeAmk: vi.fn(async () => {
    callOrder.push('storeAmk');
  }),
}));

import { commitAmk } from '../../lib/api';
import { storeAmk } from '../../lib/amk-store';
import {
  verifyAndStoreReceivedAmk,
  AmkCommitMismatchError,
} from './pair-crypto';

const fakeAmk = () => new Uint8Array(32).fill(7);

describe('verifyAndStoreReceivedAmk', () => {
  beforeEach(() => {
    callOrder.length = 0;
    vi.clearAllMocks();
  });
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('calls commitAmk BEFORE storeAmk on success', async () => {
    await verifyAndStoreReceivedAmk({
      sessionToken: 'tok',
      userId: 'u1',
      amk: fakeAmk(),
    });
    const commitIdx = callOrder.indexOf('commitAmk');
    const storeIdx = callOrder.indexOf('storeAmk');
    expect(commitIdx).toBeGreaterThanOrEqual(0);
    expect(storeIdx).toBeGreaterThanOrEqual(0);
    expect(commitIdx).toBeLessThan(storeIdx);
  });

  it('does NOT call storeAmk when commitAmk returns 409', async () => {
    (commitAmk as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('409 conflict (mismatch)'),
    );

    await expect(
      verifyAndStoreReceivedAmk({
        sessionToken: 'tok',
        userId: 'u1',
        amk: fakeAmk(),
      }),
    ).rejects.toBeInstanceOf(AmkCommitMismatchError);

    expect(storeAmk).not.toHaveBeenCalled();
  });

  it('does NOT call storeAmk when commitAmk fails for any other reason', async () => {
    (commitAmk as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('500 internal'),
    );

    await expect(
      verifyAndStoreReceivedAmk({
        sessionToken: 'tok',
        userId: 'u1',
        amk: fakeAmk(),
      }),
    ).rejects.toBeInstanceOf(Error);

    expect(storeAmk).not.toHaveBeenCalled();
  });

  it('passes the same AMK bytes to storeAmk that were verified', async () => {
    const amk = fakeAmk();
    await verifyAndStoreReceivedAmk({
      sessionToken: 'tok',
      userId: 'user-42',
      amk,
    });

    const storeMock = storeAmk as unknown as ReturnType<typeof vi.fn>;
    expect(storeMock).toHaveBeenCalledTimes(1);
    const [userId, storedAmk] = storeMock.mock.calls[0];
    expect(userId).toBe('user-42');
    expect(storedAmk).toBe(amk);
  });
});
