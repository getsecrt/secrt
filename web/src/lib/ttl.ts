export interface TtlPreset {
  label: string;
  seconds: number;
}

export const TTL_PRESETS: TtlPreset[] = [
  { label: '10 min', seconds: 600 },
  { label: '1 hr', seconds: 3600 },
  { label: '24 hrs', seconds: 86_400 },
  { label: '7 days', seconds: 604_800 },
  { label: '30 days', seconds: 2_592_000 },
  { label: '90 days', seconds: 7_776_000 },
];

export const TTL_MIN = 1;
export const TTL_MAX = 31_536_000; // 1 year
export const TTL_DEFAULT = 86_400; // 24 hours

export function isValidTtl(seconds: number): boolean {
  return Number.isFinite(seconds) && seconds >= TTL_MIN && seconds <= TTL_MAX;
}

/** Format an ISO expiry timestamp for display. */
export function formatExpiryDate(isoString: string): string {
  const date = new Date(isoString);
  if (isNaN(date.getTime())) return isoString;
  return date.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}
