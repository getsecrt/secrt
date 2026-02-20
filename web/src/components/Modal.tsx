import { useRef, useEffect, useCallback } from 'preact/hooks';
import type { ComponentChildren } from 'preact';

interface ModalProps {
  /** Whether the modal is open. */
  open: boolean;
  /** Called when the modal requests to close (Escape / backdrop click). Only fires if `dismissible` is true. */
  onClose?: () => void;
  /** Allow closing via Escape key and backdrop click. Default: true. */
  dismissible?: boolean;
  /** Extra class names for the inner card/form element. */
  class?: string;
  /** Render as a <form> instead of a <div>. */
  asForm?: boolean;
  /** Form submit handler (only used when asForm is true). */
  onSubmit?: (e: Event) => void;
  children: ComponentChildren;
  /** Accessible label for the modal dialog. */
  'aria-label'?: string;
  /** data-testid for the backdrop/dialog element. */
  'data-testid'?: string;
}

/**
 * A native <dialog>-based modal with optional dismiss behaviour.
 *
 * - Always uses `showModal()` for backdrop + focus trap + top-layer.
 * - When `dismissible` (default), Escape and backdrop click close the modal.
 * - When not `dismissible`, Escape is suppressed and backdrop clicks are ignored.
 */
export function Modal({
  open,
  onClose,
  dismissible = true,
  class: className = '',
  asForm = false,
  onSubmit,
  children,
  'aria-label': ariaLabel,
  'data-testid': testId,
}: ModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  // Sync open state with the native dialog
  useEffect(() => {
    const el = dialogRef.current;
    if (!el) return;
    if (open && !el.open) {
      el.showModal();
    } else if (!open && el.open) {
      el.close();
    }
  }, [open]);

  // Prevent native cancel (Escape) when not dismissible
  const handleCancel = useCallback(
    (e: Event) => {
      if (!dismissible) {
        e.preventDefault();
        return;
      }
      // Let native close happen, then notify parent
      onClose?.();
    },
    [dismissible, onClose],
  );

  // Backdrop click detection: clicks on the dialog element itself (not its children)
  const handleBackdropClick = useCallback(
    (e: MouseEvent) => {
      if (!dismissible) return;
      if (e.target === dialogRef.current) {
        onClose?.();
      }
    },
    [dismissible, onClose],
  );

  const Tag = asForm ? 'form' : 'div';

  return (
    <dialog
      ref={dialogRef}
      class="modal-backdrop"
      aria-modal="true"
      aria-label={ariaLabel}
      onCancel={handleCancel}
      onClick={handleBackdropClick}
      data-testid={testId}
    >
      <Tag
        class={`card relative w-full max-w-sm space-y-6 ${className}`}
        method={asForm ? 'dialog' : undefined}
        onSubmit={asForm ? onSubmit : undefined}
        onClick={(e: MouseEvent) => e.stopPropagation()}
      >
        {children}
      </Tag>
    </dialog>
  );
}
