import { publicDesktop } from './desktop-channel';
import { desktopOperation } from './desktop-transport';
import cryptoWorkerUrl from './crypto.worker?worker&url';

const TAB_SESSION = 'voltura-tab-session';
type CryptoTransport = { port: Worker | MessagePort; disconnect: () => void };

export class CryptoClient {
  private worker: CryptoTransport | undefined;
  private tabSession?: string;
  private sharedAvailable = typeof SharedWorker === 'function' && !('__TAURI_INTERNALS__' in window);
  private next = 0;
  private pending = new Map<number, { resolve: (result: unknown) => void; reject: (error: Error) => void; steps?: (done: number, total: number) => void }>();
  constructor(private progress: (text: string) => void) {
    if (!this.sharedAvailable) return;
    try {
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
      const prior = navigation?.type === 'reload' ? sessionStorage.getItem(TAB_SESSION) : null;
      if (prior && /^[a-f0-9-]{36}$/.test(prior)) this.tabSession = prior;
    } catch { this.sharedAvailable = false; }
  }
  private start() {
    const worker = this.openTransport();
    worker.port.onmessage = ({ data }) => {
      if (this.worker !== worker) return;
      if (data.progress) { this.progress(data.progress); return; }
      const request = this.pending.get(data.id); if (!request) return;
      if (data.steps) { request.steps?.(data.steps.done, data.steps.total); return; }
      this.pending.delete(data.id);
      if (data.error) request.reject(Error(data.error)); else request.resolve(data.result);
    };
    const fail = () => {
      if (this.worker !== worker) return;
      if (this.tabSession) this.sharedAvailable = false;
      this.stop('Crypto worker stopped. Unlock again.');
      window.dispatchEvent(new CustomEvent('vault-fatal', { detail: 'Crypto worker stopped. The vault has been locked.' }));
    };
    worker.port.onmessageerror = fail;
    worker.onError(event => { event.preventDefault(); fail(); });
    return worker;
  }
  private openTransport() {
    if (this.sharedAvailable) {
      try {
        this.tabSession ??= crypto.randomUUID();
        sessionStorage.setItem(TAB_SESSION, this.tabSession);
        const options = { name: this.tabSession, type: 'module', extendedLifetime: true } as const;
        const shared = new SharedWorker(cryptoWorkerUrl, options);
        return { port: shared.port, disconnect: () => shared.port.close(),
          onError: (fn: (event: Event) => void) => { shared.onerror = fn; } };
      } catch { this.tabSession = undefined; this.sharedAvailable = false; }
    }
    const worker = new Worker(new URL('./crypto.worker.ts', import.meta.url), { type: 'module' });
    const bridge = publicDesktop ? new MessageChannel() : undefined;
    if (bridge) {
      bridge.port1.onmessage = async ({ data }) => {
        try {
          const value = await desktopOperation(data);
          bridge.port1.postMessage({ id: data.id, value }, value instanceof ArrayBuffer ? [value] : []);
        } catch (error) {
          bridge.port1.postMessage({ id: data.id, error: typeof error === 'string' ? error :
            error instanceof Error ? error.message : 'Vault connection failed.' });
        }
      };
      worker.postMessage({ type: 'desktop-channel' }, [bridge.port2]);
    }
    return { port: worker, disconnect: () => { bridge?.port1.close(); worker.terminate(); },
      onError: (fn: (event: Event) => void) => { worker.onerror = fn; } };
  }
  call<T>(type: string, payload: Record<string, unknown> = {}, steps?: (done: number, total: number) => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.worker ??= this.start();
      const id = ++this.next; this.pending.set(id, { resolve: result => resolve(result as T), reject, steps });
      try { this.worker.port.postMessage({ id, type, payload }); }
      catch (error) { this.pending.delete(id); reject(error instanceof Error ? error : Error('Worker request could not be sent')); }
    });
  }
  stop(message = 'Vault locked') {
    if (this.tabSession) {
      try {
        this.worker?.port.postMessage({ id: 0, type: 'session-lock', payload: {} });
      } catch { /* The disconnected worker clears the keys when the session expires. */ }
      try { sessionStorage.removeItem(TAB_SESSION); } catch { /* Browser storage is unavailable. */ }
      this.tabSession = undefined;
    }
    this.disconnect(message);
  }
  disconnect(message = 'Vault tab closed') {
    this.worker?.disconnect(); this.worker = undefined;
    for (const p of this.pending.values()) p.reject(Error(message));
    this.pending.clear();
  }
}
