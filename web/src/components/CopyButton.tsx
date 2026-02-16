import { useState, useCallback } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { copyToClipboard } from '../lib/clipboard';

interface CopyButtonProps {
  text: string;
  class?: string;
  label?: string;
  icon?: ComponentChildren;
}

export function CopyButton({
  text,
  class: className,
  label = 'Copy',
  icon,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleClick = useCallback(async () => {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [text]);

  return (
    <button
      type="button"
      class={`btn btn-primary tracking-wider uppercase ${className ?? ''}`}
      onClick={handleClick}
    >
      {icon}
      {copied ? 'Copied!' : label}
    </button>
  );
}
