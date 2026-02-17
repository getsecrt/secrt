const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@*^_+-=?';
const CLASSES = [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] as const;

export const DEFAULT_PASSWORD_LENGTH = 20;
export const MIN_PASSWORD_LENGTH = CLASSES.length;

export interface PasswordGeneratorOptions {
  length?: number;
  grouped?: boolean;
}

type FillRandomBytes = (buffer: Uint8Array) => void;

function defaultFillRandomBytes(buffer: Uint8Array): void {
  crypto.getRandomValues(buffer);
}

function randomUsize(range: number, fillRandomBytes: FillRandomBytes): number {
  if (range <= 0) {
    throw new Error('range must be positive');
  }
  if (range === 1) {
    return 0;
  }

  if (range <= 256) {
    const limit = 256 - (256 % range);
    const buf = new Uint8Array(1);
    for (;;) {
      fillRandomBytes(buf);
      if (buf[0] < limit) {
        return buf[0] % range;
      }
    }
  }

  const total = 0x1_0000_0000;
  const limit = total - (total % range);
  const buf = new Uint8Array(4);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

  for (;;) {
    fillRandomBytes(buf);
    const value = view.getUint32(0, true);
    if (value < limit) {
      return value % range;
    }
  }
}

function randomChar(charset: string, fillRandomBytes: FillRandomBytes): string {
  return charset[randomUsize(charset.length, fillRandomBytes)];
}

function shuffle<T>(items: T[], fillRandomBytes: FillRandomBytes): void {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = randomUsize(i + 1, fillRandomBytes);
    [items[i], items[j]] = [items[j], items[i]];
  }
}

function generateUngrouped(
  length: number,
  classes: readonly string[],
  fillRandomBytes: FillRandomBytes,
): string {
  const combined = classes.join('');
  const chars: string[] = [];

  for (const cls of classes) {
    chars.push(randomChar(cls, fillRandomBytes));
  }

  while (chars.length < length) {
    chars.push(randomChar(combined, fillRandomBytes));
  }

  shuffle(chars, fillRandomBytes);
  return chars.join('');
}

function generateGrouped(
  length: number,
  classes: readonly string[],
  fillRandomBytes: FillRandomBytes,
): string {
  const counts = new Array<number>(classes.length).fill(1);
  const remaining = length - classes.length;
  for (let i = 0; i < remaining; i += 1) {
    const idx = randomUsize(classes.length, fillRandomBytes);
    counts[idx] += 1;
  }

  const groups = classes.map((cls, i) => {
    const group: string[] = [];
    for (let j = 0; j < counts[i]; j += 1) {
      group.push(randomChar(cls, fillRandomBytes));
    }
    shuffle(group, fillRandomBytes);
    return group;
  });

  for (let i = groups.length - 1; i > 0; i -= 1) {
    const j = randomUsize(i + 1, fillRandomBytes);
    [groups[i], groups[j]] = [groups[j], groups[i]];
  }

  return groups.flat().join('');
}

export function generatePassword(
  options: PasswordGeneratorOptions = {},
  fillRandomBytes: FillRandomBytes = defaultFillRandomBytes,
): string {
  const length = options.length ?? DEFAULT_PASSWORD_LENGTH;
  if (!Number.isInteger(length) || length < 1) {
    throw new Error(
      `length must be a positive integer, got ${JSON.stringify(length)}`,
    );
  }

  if (length < CLASSES.length) {
    throw new Error(
      `length ${length} is too short; need at least ${CLASSES.length} for the enabled character classes`,
    );
  }

  if (options.grouped) {
    return generateGrouped(length, CLASSES, fillRandomBytes);
  }

  return generateUngrouped(length, CLASSES, fillRandomBytes);
}
