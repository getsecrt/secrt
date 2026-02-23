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
import { AppLoginPage } from './features/auth/AppLoginPage';
import { SyncPage } from './features/sync/SyncPage';
import { AboutPage } from './features/about/AboutPage';
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

  useEffect(() => {
    const titles: Record<string, string> = {
      send: 'secrt',
      claim: 'Claim Secret — secrt',
      sync: 'Sync Key — secrt',
      'how-it-works': 'How It Works — secrt',
      privacy: 'Privacy — secrt',
      login: 'Log In — secrt',
      register: 'Register — secrt',
      dashboard: 'Dashboard — secrt',
      settings: 'Settings — secrt',
      device: 'Approve Device — secrt',
      'app-login': 'Authorize App — secrt',
      about: 'About — secrt',
      'not-found': 'Not Found — secrt',
    };
    document.title = titles[route.page] ?? 'secrt';
  }, [route.page]);

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
    case 'app-login':
      page = <AppLoginPage />;
      break;
    case 'about':
      page = <AboutPage />;
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
      <Layout maxWidth={route.page === 'dashboard' ? 'max-w-5xl' : undefined}>
        {page}
      </Layout>
    </AuthProvider>
  );
}
