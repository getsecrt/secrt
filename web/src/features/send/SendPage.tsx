export function SendPage() {
  return (
    <>
      <div class="card">
        <h3 class="label text-center">Create a secret</h3>
        <p class="">
          Secrets are encrypted in your browser before leaving your device. The
          server only stores ciphertext and deletes it after a single retrieval.
        </p>
      </div>

      <div class="card text-center text-muted">Send UI coming in Phase 1.</div>
      <button class="btn" type="button">
        Click Me!
      </button>
      <button class="btn btn-primary" type="button">
        Submit
      </button>
    </>
  );
}
