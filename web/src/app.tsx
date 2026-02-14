import { useRoute } from './router';
import { Layout } from './components/Layout';
import { SendPage } from './features/send/SendPage';
import { ClaimPage } from './features/claim/ClaimPage';
import { ThemePage } from './features/test/ThemePage';

export function App() {
  const route = useRoute();

  if (route.page === 'theme') {
    return <ThemePage />;
  }

  let page;
  switch (route.page) {
    case 'send':
      page = <SendPage />;
      break;
    case 'claim':
      page = <ClaimPage id={route.id} />;
      break;
    case 'not-found':
      page = (
        <div class="card text-center">
          <h2 class="label">Not found</h2>
          <p class="text-sm text-muted">This page doesn't exist.</p>
        </div>
      );
      break;
  }

  return <Layout>{page}</Layout>;
}
