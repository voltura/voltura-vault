import { useEffect, useEffectEvent, useState } from 'react';
import { Icon } from './Icon';

export function Toast({ message, kind = 'status', onDismiss }: {
  message: string; kind?: 'status' | 'progress' | 'error'; onDismiss?: () => void;
}) {
  const [dismissed, setDismissed] = useState(false);
  function dismiss() {
    setDismissed(true);
    onDismiss?.();
  }
  const dismissOnTimeout = useEffectEvent(dismiss);
  useEffect(() => {
    if (kind !== 'status' || dismissed) return;
    const timer = window.setTimeout(() => dismissOnTimeout(), 10_000);
    return () => window.clearTimeout(timer);
  }, [kind, message, dismissed]);
  if (dismissed) return null;
  return <div className={`app-toast app-toast-${kind}`}>
    <div className="app-toast-message" role={kind === 'error' ? 'alert' : 'status'}>
      <span className="app-toast-symbol" aria-hidden="true">
        {kind === 'progress' ? <span className="spinner"/> : <Icon name={kind === 'error' ? 'alert' : 'info'}/>}
      </span>
      <span>{message}</span>
    </div>
    {kind !== 'progress' && <button type="button" className="icon-button" aria-label="Dismiss notification"
      onClick={dismiss}><Icon name="close"/></button>}
    {kind === 'status' && <span className="app-toast-timer" aria-hidden="true">
      <span/>
    </span>}
  </div>;
}
