import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, cleanup, fireEvent } from '@testing-library/preact';
import { ThemeToggle } from './ThemeToggle';

describe('ThemeToggle', () => {
  beforeEach(() => {
    document.documentElement.classList.remove('dark');
    localStorage.clear();
    cleanup();
  });

  it('renders switch with accessible label', () => {
    render(<ThemeToggle />);
    expect(screen.getByRole('switch', { name: 'Toggle dark mode' })).toBeInTheDocument();
  });

  it('toggles dark mode on click', () => {
    render(<ThemeToggle />);
    const btn = screen.getByRole('switch');
    fireEvent.click(btn);
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    fireEvent.click(btn);
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('"d" key shortcut toggles theme', () => {
    render(<ThemeToggle />);
    fireEvent.keyDown(document, { key: 'd' });
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    fireEvent.keyDown(document, { key: 'd' });
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('ignores "d" when meta key held', () => {
    render(<ThemeToggle />);
    fireEvent.keyDown(document, { key: 'd', metaKey: true });
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('ignores "d" when target is an input', () => {
    render(
      <div>
        <ThemeToggle />
        <input data-testid="text-input" />
      </div>,
    );
    const input = screen.getByTestId('text-input');
    fireEvent.keyDown(input, { key: 'd' });
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('cleans up keydown listener on unmount', () => {
    const { unmount } = render(<ThemeToggle />);
    unmount();
    fireEvent.keyDown(document, { key: 'd' });
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });
});
