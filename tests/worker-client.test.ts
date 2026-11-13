import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { CryptoClient } from '../src/worker-client';

class TestWorker {
  static instances: TestWorker[] = [];
  onmessage?: (event: { data: unknown }) => void;
  onerror?: (event: { preventDefault(): void }) => void;
  onmessageerror?: () => void;
  terminate = vi.fn();
  postMessage = vi.fn();
  constructor() { TestWorker.instances.push(this); }
}
beforeEach(() => {
  TestWorker.instances = [];
  vi.stubGlobal('Worker', TestWorker);
  vi.stubGlobal('window', new EventTarget());
});
afterEach(() => vi.unstubAllGlobals());

it('locks by terminating and rejecting pending work without starting another worker', async () => {
  const client = new CryptoClient(() => {});
  expect(TestWorker.instances).toHaveLength(0);
  const request = client.call('unlock');
  const rejected = expect(request).rejects.toThrow('Vault locked');
  client.stop(); await rejected;
  expect(TestWorker.instances).toHaveLength(1);
  expect(TestWorker.instances[0].terminate).toHaveBeenCalledOnce();
});

it('ignores a late result and error from a terminated worker after unlocking again', async () => {
  const client = new CryptoClient(() => {}), fatal = vi.fn();
  window.addEventListener('vault-fatal', fatal);
  const oldRequest = client.call('unlock');
  const rejected = expect(oldRequest).rejects.toThrow();
  const old = TestWorker.instances[0]; client.stop(); await rejected;
  const newRequest = client.call<string>('unlock');
  const next = TestWorker.instances[1];
  const id = next.postMessage.mock.calls[0][0].id;
  old.onmessage?.({ data: { id, result: 'stale plaintext' } });
  old.onerror?.({ preventDefault() {} });
  next.onmessage?.({ data: { id, result: 'current result' } });
  expect(await newRequest).toBe('current result');
  expect(fatal).not.toHaveBeenCalled();
  expect(next.terminate).not.toHaveBeenCalled();
});

it.each(['error', 'messageerror'])('locks the UI and rejects pending work on worker %s', async kind => {
  const client = new CryptoClient(() => {}), fatal = vi.fn();
  window.addEventListener('vault-fatal', fatal);
  const pending = client.call('save'), rejected = expect(pending).rejects.toThrow('Crypto worker stopped');
  const worker = TestWorker.instances[0];
  if (kind === 'error') worker.onerror?.({ preventDefault() {} }); else worker.onmessageerror?.();
  await rejected;
  expect(fatal).toHaveBeenCalledOnce();
  expect(worker.terminate).toHaveBeenCalledOnce();
  expect(TestWorker.instances).toHaveLength(1);
});
