import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { TtlSelector } from './TtlSelector';
import { TTL_PRESETS } from '../../lib/ttl';

describe('TtlSelector', () => {
  afterEach(() => cleanup());

  it('renders all TTL preset buttons', () => {
    render(<TtlSelector value={86400} onChange={() => {}} />);
    for (const preset of TTL_PRESETS) {
      expect(screen.getByRole('button', { name: preset.label })).toBeInTheDocument();
    }
  });

  it('active preset has aria-pressed="true"', () => {
    render(<TtlSelector value={3600} onChange={() => {}} />);
    expect(screen.getByRole('button', { name: '1 hr' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(screen.getByRole('button', { name: '10 min' })).toHaveAttribute(
      'aria-pressed',
      'false',
    );
  });

  it('calls onChange(seconds) when a preset is clicked', async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<TtlSelector value={86400} onChange={onChange} />);
    await user.click(screen.getByRole('button', { name: '7 days' }));
    expect(onChange).toHaveBeenCalledWith(604800);
  });

  it('shows "Expires After" legend', () => {
    render(<TtlSelector value={86400} onChange={() => {}} />);
    expect(screen.getByText('Expires After')).toBeInTheDocument();
  });

  it('all buttons disabled when disabled prop is true', () => {
    render(<TtlSelector value={86400} onChange={() => {}} disabled />);
    const buttons = screen.getAllByRole('button');
    for (const btn of buttons) {
      expect(btn).toBeDisabled();
    }
  });
});
