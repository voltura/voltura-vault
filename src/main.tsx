import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';
import './skins.css';

createRoot(document.getElementById('root')!).render(<App />);
if (import.meta.env.PROD && 'serviceWorker' in navigator && !('__TAURI_INTERNALS__' in window)) {
  navigator.serviceWorker.register('/sw.js').catch(() => {
    window.dispatchEvent(new CustomEvent('vault-status', { detail: 'Offline installation failed. Keep this page open and check browser storage.' }));
  });
}
