import { useState, useEffect } from 'preact/hooks';
import { useRoute } from './router';
import { Layout } from './components/Layout';
import { AuthProvider } from './lib/auth-context';
import { SendPage } from './features/send/SendPage';
import { ClaimPage } from './features/claim/ClaimPage';
import { HowItWorksPage } from './features/trust/HowItWorksPage';
import { PrivacyPage } from './features/trust/PrivacyPage';
import { LoginPage } from './features/auth/LoginPage';
import { RegisterPage } from './features/auth/RegisterPage';
import { DashboardPage } from './features/dashboard/DashboardPage';
import { SettingsPage } from './features/settings/SettingsPage';
import { DevicePage } from './features/auth/DevicePage';
import { SyncPage } from './features/sync/SyncPage';
import { ThemePage } from './features/test/ThemePage';

export function App() {
  const route = useRoute();

  // Counter increments on every navigation so SendPage remounts
  // (resets form state) when "Create" is clicked from the result screen.
  const [navKey, setNavKey] = useState(0);
  useEffect(() => {
    const onNav = () => setNavKey((k) => k + 1);
    window.addEventListener('popstate', onNav);
    return () => window.removeEventListener('popstate', onNav);
  }, []);

  if (import.meta.env.DEV && route.page === 'theme') {
    return <ThemePage />;
  }

  let page;
  switch (route.page) {
    case 'send':
      page = <SendPage key={navKey} />;
      break;
    case 'claim':
      page = <ClaimPage id={route.id} />;
      break;
    case 'sync':
      page = <SyncPage id={route.id} />;
      break;
    case 'how-it-works':
      page = <HowItWorksPage />;
      break;
    case 'privacy':
      page = <PrivacyPage />;
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
    case 'device':
      page = <DevicePage />;
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
