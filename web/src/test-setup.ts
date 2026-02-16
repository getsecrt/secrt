import '@testing-library/jest-dom/vitest';

// jsdom lacks <dialog> methods — polyfill for tests
if (!HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.setAttribute('open', '');
  };
}
if (!HTMLDialogElement.prototype.close) {
  HTMLDialogElement.prototype.close = function close() {
    this.removeAttribute('open');
  };
}

const POPOVER_OPEN_ATTR = 'data-popover-open';
const nativeMatches = HTMLElement.prototype.matches;

if (!HTMLElement.prototype.showPopover) {
  HTMLElement.prototype.showPopover = function showPopover() {
    this.setAttribute(POPOVER_OPEN_ATTR, 'true');
    this.dispatchEvent(new Event('toggle'));
  };
}

if (!HTMLElement.prototype.hidePopover) {
  HTMLElement.prototype.hidePopover = function hidePopover() {
    this.removeAttribute(POPOVER_OPEN_ATTR);
    this.dispatchEvent(new Event('toggle'));
  };
}

if (!HTMLElement.prototype.togglePopover) {
  HTMLElement.prototype.togglePopover = function togglePopover(force?: boolean) {
    const shouldOpen =
      force === undefined ? !this.hasAttribute(POPOVER_OPEN_ATTR) : force;
    if (shouldOpen) {
      this.showPopover();
    } else {
      this.hidePopover();
    }
  };
}

HTMLElement.prototype.matches = function patchedMatches(selector: string) {
  if (selector === ':popover-open') {
    return this.hasAttribute(POPOVER_OPEN_ATTR);
  }
  return nativeMatches.call(this, selector);
};
