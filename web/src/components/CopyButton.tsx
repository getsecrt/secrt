import { useState, useCallback } from 'preact/hooks';

interface CopyButtonProps {
  text: string;
  class?: string;
  label?: string;
}

export function CopyButton({
  text,
  class: className,
  label = 'Copy',
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [text]);

  return (
    <button
      type="button"
      class={`btn btn-sm btn-secondary ${className ?? ''}`}
      onClick={handleClick}
    >
      {copied ? 'Copied!' : label}
    </button>
  );
}
