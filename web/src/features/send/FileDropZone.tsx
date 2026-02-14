import { useState, useCallback, useRef } from 'preact/hooks';
import { UploadIcon, XMarkIcon } from '../../components/Icons';
import { formatSize } from '../../lib/format';

interface FileDropZoneProps {
  file: File | null;
  onFileSelect: (f: File) => void;
  onFileClear: () => void;
  disabled?: boolean;
  className?: string;
}

export function FileDropZone({
  file,
  onFileSelect,
  onFileClear,
  disabled,
  className: className,
}: FileDropZoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      if (!disabled) setDragOver(true);
    },
    [disabled],
  );

  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      if (disabled) return;
      const f = e.dataTransfer?.files[0];
      if (f) onFileSelect(f);
    },
    [disabled, onFileSelect],
  );

  const handleClick = useCallback(() => {
    if (!disabled) inputRef.current?.click();
  }, [disabled]);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handleClick();
      }
    },
    [handleClick],
  );

  const handleInputChange = useCallback(
    (e: Event) => {
      const f = (e.target as HTMLInputElement).files?.[0];
      if (f) onFileSelect(f);
    },
    [onFileSelect],
  );

  if (file) {
    return (
      <div class={`flex items-center gap-3 rounded-md border border-border bg-surface px-3 py-3 ${className ?? ''}`}>
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm font-medium">{file.name}</p>
          <p class="text-xs text-muted">{formatSize(file.size)}</p>
        </div>
        <button
          type="button"
          class="shrink-0 rounded p-1 text-muted hover:text-text"
          onClick={onFileClear}
          disabled={disabled}
          aria-label="Remove file"
        >
          <XMarkIcon class="size-4" />
        </button>
      </div>
    );
  }

  return (
    <div
      role="button"
      tabIndex={0}
      class={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed px-4 py-6 text-center transition-colors ${
        dragOver
          ? 'border-accent bg-accent/5'
          : 'border-border hover:border-accent/40'
      } ${disabled ? 'pointer-events-none opacity-50' : ''} ${className ?? ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <UploadIcon class="size-8 text-muted" />
      <p class="text-sm text-muted">Drop a file or click to browse</p>
      <input
        ref={inputRef}
        type="file"
        class="hidden"
        onChange={handleInputChange}
        disabled={disabled}
      />
    </div>
  );
}
