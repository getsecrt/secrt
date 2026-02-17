import type { ComponentChildren } from 'preact';

interface CardHeadingProps {
  title: string;
  subtitle?: ComponentChildren;
  icon?: ComponentChildren;
  underline?: boolean;
  class?: string;
}

export function CardHeading({
  title,
  subtitle,
  icon,
  underline,
  class: className,
}: CardHeadingProps) {
  return (
    <h2
      class={`-m-1 pb-3 text-center ${underline ? 'mb-5 border-b border-border pb-3' : 'mb-3'} ${className ?? ''}`}
    >
      {icon && <div class="mb-1 mb-2 flex justify-center">{icon}</div>}
      <div class="pb-1 text-xl font-semibold tracking-widest text-neutral-700 uppercase dark:text-neutral-300 dark:text-shadow-black">
        {title}
      </div>
      {subtitle && (
        <div class="text-sm leading-tight whitespace-pre-line text-muted">
          {subtitle}
        </div>
      )}
    </h2>
  );
}
