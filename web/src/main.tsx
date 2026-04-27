import { render } from 'preact';
import { App } from './app';
import { registerServiceWorker } from './lib/pwa';
import './styles.css';

const root = document.getElementById('app');
if (!root) {
  throw new Error('missing #app root element');
}

// Clear any existing tree first (prevents HMR double-mount)
root.replaceChildren();
render(<App />, root);
registerServiceWorker();
