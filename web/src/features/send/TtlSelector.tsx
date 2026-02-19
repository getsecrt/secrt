import { useCallback } from 'preact/hooks';
import { TTL_PRESETS } from '../../lib/ttl';
import { ClockIcon } from '../../components/Icons';

interface TtlSelectorProps {
  value: number;
  onChange: (seconds: number) => void;
  disabled?: boolean;
}

export function TtlSelector({ value, onChange, disabled }: TtlSelectorProps) {
  const handlePresetClick = useCallback(
    (seconds: number) => {
      onChange(seconds);
    },
    [onChange],
  );

  return (
    <fieldset class="space-y-2" disabled={disabled}>
      <legend class="label">
        <ClockIcon class="size-4 opacity-60" />
        Expires After
      </legend>
      <div class="flex flex-wrap justify-center gap-1.5">
        {TTL_PRESETS.map((preset) => (
          <button
            key={preset.seconds}
            type="button"
            aria-pressed={preset.seconds === value}
            class={`rounded-full border px-3 py-1 text-xs font-medium text-muted transition-colors ${
              preset.seconds === value
                ? 'border-green-600 bg-green-500 text-white'
                : 'border-border bg-neutral-200 hover:text-text dark:bg-neutral-800'
            }`}
            onClick={() => handlePresetClick(preset.seconds)}
          >
            {preset.label}
          </button>
        ))}
      </div>
    </fieldset>
  );
}
