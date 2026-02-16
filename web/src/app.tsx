import { useRoute } from './router';
import { Layout } from './components/Layout';
import { AuthProvider } from './lib/auth-context';
import { SendPage } from './features/send/SendPage';
import { ClaimPage } from './features/claim/ClaimPage';
import { HowItWorksPage } from './features/trust/HowItWorksPage';
import { LoginPage } from './features/auth/LoginPage';
import { RegisterPage } from './features/auth/RegisterPage';
import { DashboardPage } from './features/dashboard/DashboardPage';
import { SettingsPage } from './features/settings/SettingsPage';
import { ThemePage } from './features/test/ThemePage';

export function App() {
  const route = useRoute();

  if (import.meta.env.DEV && route.page === 'theme') {
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
    case 'how-it-works':
      page = <HowItWorksPage />;
      break;
    case 'login':
      page = <LoginPage />;
      break;
    case 'register':
      page = <RegisterPage />;
      break;
    case 'dashboard':
      page = <DashboardPage />;
      break;
    case 'settings':
      page = <SettingsPage />;
      break;
    case 'not-found':
      page = (
        <div class="card text-center">
          <h2 class="label">Not found</h2>
          <p class="text-muted">This page doesn't exist.</p>
        </div>
      );
      break;
  }

  return (
    <AuthProvider>
      <Layout>{page}</Layout>
    </AuthProvider>
  );
}
