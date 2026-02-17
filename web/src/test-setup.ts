import '@testing-library/jest-dom/vitest';

// Node 21+ ships a built-in localStorage that shadows happy-dom's when
// --localstorage-file is absent.  The built-in is non-functional (no methods),
// so we replace it with a simple in-memory implementation.
if (
  typeof localStorage !== 'undefined' &&
  typeof localStorage.clear !== 'function'
) {
  const data = new Map<string, string>();
  const storage: Storage = {
    get length() {
      return data.size;
    },
    clear() {
      data.clear();
    },
    getItem(key: string) {
      return data.get(key) ?? null;
    },
    key(index: number) {
      return [...data.keys()][index] ?? null;
    },
    removeItem(key: string) {
      data.delete(key);
    },
    setItem(key: string, value: string) {
      data.set(key, String(value));
    },
  };
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: storage,
  });
}

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
  HTMLElement.prototype.togglePopover = function togglePopover(
    force?: boolean,
  ): boolean {
    const shouldOpen =
      force === undefined ? !this.hasAttribute(POPOVER_OPEN_ATTR) : force;
    if (shouldOpen) {
      this.showPopover();
    } else {
      this.hidePopover();
    }
    return shouldOpen;
  };
}

HTMLElement.prototype.matches = function patchedMatches(selector: string) {
  if (selector === ':popover-open') {
    return this.hasAttribute(POPOVER_OPEN_ATTR);
  }
  return nativeMatches.call(this, selector);
};
