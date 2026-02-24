import { useState, useCallback } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { copyToClipboard, copySensitive } from '../lib/clipboard';

interface CopyButtonProps {
  text: string;
  class?: string;
  label?: ComponentChildren;
  icon?: ComponentChildren;
  sensitive?: boolean;
}

export function CopyButton({
  text,
  class: className,
  label = 'Copy',
  icon,
  sensitive,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleClick = useCallback(async () => {
    const ok = await (sensitive ? copySensitive : copyToClipboard)(text);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [text, sensitive]);

  return (
    <button
      type="button"
      class={`btn btn-primary tracking-wider uppercase ${className ?? ''}`}
      onClick={handleClick}
      aria-live="polite"
    >
      {icon}
      {copied ? 'Copied!' : label}
    </button>
  );
}
