interface ClaimPageProps {
  id: string;
}

export function ClaimPage({ id }: ClaimPageProps) {
  return (
    <>
      <div class="card">
        <h2 class="label">Claim a secret</h2>
        <p class="text-sm text-muted">
          Someone shared a secret with you. Claiming it will decrypt the content
          in your browser and permanently delete it from the server.
        </p>
      </div>

      <div class="card text-center text-sm text-muted">
        <p>
          Secret ID: <span class="code select-all">{id}</span>
        </p>
        <p class="mt-2">Claim UI coming in Phase 1.</p>
      </div>
    </>
  );
}
