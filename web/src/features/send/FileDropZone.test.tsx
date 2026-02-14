import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup, fireEvent } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { FileDropZone } from './FileDropZone';

describe('FileDropZone', () => {
  afterEach(() => cleanup());

  const noop = () => {};

  it('empty state shows "Drop a file or click to browse"', () => {
    render(<FileDropZone file={null} onFileSelect={noop} onFileClear={noop} />);
    expect(screen.getByText('Drop a file or click to browse')).toBeInTheDocument();
  });

  it('calls onFileSelect on file drop', () => {
    const onFileSelect = vi.fn();
    render(<FileDropZone file={null} onFileSelect={onFileSelect} onFileClear={noop} />);
    const dropZone = screen.getByRole('button');
    const file = new File(['content'], 'test.txt', { type: 'text/plain' });
    fireEvent.drop(dropZone, {
      dataTransfer: { files: [file] },
    });
    expect(onFileSelect).toHaveBeenCalledWith(file);
  });

  it('calls onFileSelect on hidden input change', () => {
    const onFileSelect = vi.fn();
    render(<FileDropZone file={null} onFileSelect={onFileSelect} onFileClear={noop} />);
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(['data'], 'doc.pdf', { type: 'application/pdf' });
    // Simulate file selection via the hidden input
    Object.defineProperty(input, 'files', { value: [file], writable: false });
    fireEvent.change(input);
    expect(onFileSelect).toHaveBeenCalledWith(file);
  });

  it('does not call onFileSelect on drop when disabled', () => {
    const onFileSelect = vi.fn();
    render(<FileDropZone file={null} onFileSelect={onFileSelect} onFileClear={noop} disabled />);
    const dropZone = screen.getByRole('button');
    const file = new File(['content'], 'test.txt');
    fireEvent.drop(dropZone, {
      dataTransfer: { files: [file] },
    });
    expect(onFileSelect).not.toHaveBeenCalled();
  });

  it('file selected state shows filename and formatted size', () => {
    const file = new File(['a'.repeat(2048)], 'photo.png', { type: 'image/png' });
    render(<FileDropZone file={file} onFileSelect={noop} onFileClear={noop} />);
    expect(screen.getByText('photo.png')).toBeInTheDocument();
    expect(screen.getByText('2.0 KB')).toBeInTheDocument();
  });

  it('calls onFileClear on remove button click', async () => {
    const onFileClear = vi.fn();
    const user = userEvent.setup();
    const file = new File(['data'], 'file.txt');
    render(<FileDropZone file={file} onFileSelect={noop} onFileClear={onFileClear} />);
    await user.click(screen.getByRole('button', { name: 'Remove file' }));
    expect(onFileClear).toHaveBeenCalledOnce();
  });

  it('disables remove button when disabled', () => {
    const file = new File(['data'], 'file.txt');
    render(<FileDropZone file={file} onFileSelect={noop} onFileClear={noop} disabled />);
    expect(screen.getByRole('button', { name: 'Remove file' })).toBeDisabled();
  });

  it('Enter key triggers file picker', () => {
    render(<FileDropZone file={null} onFileSelect={noop} onFileClear={noop} />);
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    // Replace click with a mock to avoid click event bubbling back to the parent
    const clickMock = vi.fn();
    input.click = clickMock;
    const dropZone = screen.getByRole('button');
    fireEvent.keyDown(dropZone, { key: 'Enter' });
    expect(clickMock).toHaveBeenCalled();
  });
});
