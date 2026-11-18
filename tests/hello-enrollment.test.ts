import 'fake-indexeddb/auto';
import { expect, it, vi } from 'vitest';
import { createVault, ready, sodium } from '../src/crypto';
import { saveInitial } from '../src/storage';

it('limits password-free Hello setup to one use after a recent master password unlock', async () => {
  await ready();
  const password = 'synthetic-master-password';
  const { envelope, root } = createVault(password, {
    algorithm: 'argon2id13', memory: 64 * 1024 ** 2, passes: 3, salt: sodium.randombytes_buf(16),
  });
  root.fill(0);
  await saveInitial(envelope);

  type Reply = { result?: unknown; error?: string };
  let reply: (value: Reply) => void;
  const worker = {
    location: new URL('https://tauri.localhost'),
    onmessage: undefined as ((event: { data: unknown }) => void) | undefined,
    postMessage: (value: Reply) => reply(value),
  };
  const call = (type: string, payload: Record<string, unknown> = {}) => new Promise<Reply>(resolve => {
    reply = resolve;
    worker.onmessage!({ data: { id: 1, type, payload, windows: true } });
  });
  const idleMs = 600_000;
  const secret = new Uint8Array(32).fill(7);
  const credential = { id: 'AQID', input: new Uint8Array(32).fill(3) };
  const unlock = () => call('unlock', { password, idleMs });
  const enroll = (token: unknown) => call('hello-enroll', { token, credential, secret: secret.slice() });
  const setupDeadline = async () => (await call('status')).result as { helloSetupUntil?: number };

  vi.stubGlobal('self', worker);
  try {
    await import('../src/crypto.worker');
    expect((await call('hello-confirm')).error).toBeDefined();

    expect((await unlock()).error).toBeUndefined();
    expect((await setupDeadline()).helloSetupUntil).toBeGreaterThan(Date.now());
    const confirmation = await call('hello-confirm');
    expect(confirmation.result).toEqual(expect.any(String));
    expect((await enroll(confirmation.result)).error).toBeUndefined();
    expect((await setupDeadline()).helloSetupUntil).toBeUndefined();
    expect((await call('hello-confirm')).error).toContain('Confirm your master password');

    await call('session-lock');
    expect((await call('hello-unlock', { id: credential.id, secret: secret.slice(), idleMs })).error).toBeUndefined();
    expect((await setupDeadline()).helloSetupUntil).toBeUndefined();
    expect((await call('hello-confirm')).error).toContain('Confirm your master password');

    await call('session-lock');
    expect((await unlock()).error).toBeUndefined();
    const expires = (await setupDeadline()).helloSetupUntil!;
    vi.spyOn(Date, 'now').mockReturnValue(expires + 1);
    expect((await setupDeadline()).helloSetupUntil).toBeUndefined();
    expect((await call('hello-confirm')).error).toContain('Confirm your master password');
    const explicit = await call('hello-confirm', { password });
    expect(explicit.result).toEqual(expect.any(String));

    await call('session-lock');
    expect((await unlock()).error).toBeUndefined();
    expect((await enroll(explicit.result)).error).toContain('Confirm your master password again');
  } finally {
    if (worker.onmessage) await call('session-lock');
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
});
