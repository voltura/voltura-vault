import { useCallback, useEffect, useRef, useState } from 'react';

export const buildVersion: string = import.meta.env.VITE_VAULT_BUILD_VERSION;
const checkEnabled = import.meta.env.PROD && !('__TAURI_INTERNALS__' in window);

export function useWebUpdate() {
  const [available, setAvailable] = useState<string>();
  const [dismissed, setDismissed] = useState<string>();
  const [checking, setChecking] = useState(false);
  const [feedback, setFeedback] = useState<{ message: string; kind: 'status' | 'error' }>();
  const pending = useRef<Promise<string | undefined> | undefined>(undefined);

  const check = useCallback(() => {
    pending.current ??= (async () => {
      const response = await fetch('/version.json', {
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(8000),
      });
      if (!response.ok) throw Error('Version check failed');
      const { version } = await response.json();
      if (typeof version !== 'string' || !/^[\w.+-]{1,50}$/.test(version)) throw Error('Invalid version');
      const next = version === buildVersion ? undefined : version;
      setAvailable(next);
      if (next) setFeedback(undefined);
      return next;
    })().finally(() => { pending.current = undefined; });
    return pending.current;
  }, []);

  useEffect(() => {
    if (!checkEnabled) return;
    const foreground = () => {
      if (!document.hidden && navigator.onLine) void check().catch(() => {});
    };
    foreground();
    const timer = window.setInterval(foreground, 60_000);
    window.addEventListener('pageshow', foreground);
    window.addEventListener('focus', foreground);
    window.addEventListener('online', foreground);
    document.addEventListener('visibilitychange', foreground);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('pageshow', foreground);
      window.removeEventListener('focus', foreground);
      window.removeEventListener('online', foreground);
      document.removeEventListener('visibilitychange', foreground);
    };
  }, [check]);

  if (!checkEnabled) return undefined;
  return {
    version: available !== dismissed ? available : undefined,
    checking,
    feedback,
    dismissFeedback: () => setFeedback(undefined),
    dismiss: () => setDismissed(available),
    check: async () => {
      setChecking(true);
      setFeedback(undefined);
      try {
        if (await check()) setDismissed(undefined);
        else setFeedback({ message: 'You’re up to date.', kind: 'status' });
      } catch {
        setFeedback({
          message: navigator.onLine ? 'Could not check for updates.' : 'Connect to check for updates.',
          kind: 'error',
        });
      } finally {
        setChecking(false);
      }
    },
  };
}
