import 'fake-indexeddb/auto';
import { expect, it, vi } from 'vitest';
import { openDB } from 'idb';
import { generatorHistory, recoverGeneratorHistory, retireGeneratorHistory } from '../src/generator-history';
import { createRotatedVault, createVault, encryptRecord, ready, sodium } from '../src/crypto';
import { context, type Kdf } from '../src/format';
import { db, saveInitial, saveRevision } from '../src/storage';
import { initializeRemote, withVaultSession } from '../src/sync';

it('replaces a test cache only after the protected recovery file, password and server login succeed', async () => {
  await ready();
  let reply: (value: { result?: unknown; error?: string }) => void = () => undefined;
  const worker = {
    location: new URL('https://tauri.localhost'),
    onmessage: undefined as ((event: { data: unknown }) => void) | undefined,
    postMessage: (value: Parameters<typeof reply>[0]) => reply(value),
  };
  let encryptedConfig: string;
  let allowSignIn = false;
  const kdf: Kdf = { algorithm: 'argon2id13', memory: 64 * 1024 ** 2, passes: 3, salt: sodium.randombytes_buf(16) };
  const bytes = () => sodium.randombytes_buf(32);
  const old = createVault('old-test-password', kdf);
  const oldRecord = encryptRecord('unsynced test note', old.root, context(old.envelope.context.vaultId), []);
  await saveInitial(old.envelope);
  await saveRevision(oldRecord);
  const account = bytes(), recoveryKey = bytes(), deviceKey = bytes();
  const password = 'new-synthetic-vault-password';
  const current = createVault(password, kdf, account, { recoveryKey, deviceKey });
  const file = (key: Uint8Array) => new Blob(['voltura-vault-recovery-v1\n', sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING), '\n']);

  vi.stubGlobal('self', worker);
  vi.stubGlobal('navigator', { locks: { request: (_name: string, action: () => Promise<unknown>) => action() } });
  vi.stubGlobal('fetch', async (url: string, options: RequestInit) => {
    switch (new URL(url).pathname.split('/').at(-1)) {
      case 'bootstrap':
        encryptedConfig = JSON.parse(String(options.body)).encryptedConfig;
        return new Response(null, { status: 204 });
      case 'config':
        return Response.json({ encryptedConfig, vaultId: current.envelope.context.vaultId });
      case 'sessions':
        return allowSignIn ? Response.json({ token: 'a'.repeat(43), writeChallenge: 'b'.repeat(43) }) : new Response(null, { status: 401 });
      case 'session':
        return new Response(null, { status: 204 });
      default:
        throw Error('Unexpected API request in recovery test');
    }
  });

  try {
    await initializeRemote(current.envelope, account, bytes(), 'a'.repeat(43));
    await expect(withVaultSession(old.envelope, account, async () => undefined))
      .rejects.toThrow('This device opened a different vault');
    await expect(withVaultSession(current.envelope, account, async () => undefined))
      .rejects.toThrow('The vault server rejected sign-in');
    await import('../src/crypto.worker');
    const call = (type: string, payload: Record<string, unknown>) => new Promise<Parameters<typeof reply>[0]>(resolve => {
      reply = resolve;
      worker.onmessage!({ data: { id: 1, type, payload } });
    });
    const storage = await db();
    const attempt = (pass: string, key: Uint8Array) => call('unlock', { password: pass, recoveryFile: file(key), idleMs: 300000 });
    expect((await attempt(password, bytes())).error).toMatch(/Could not unlock/);
    expect((await attempt('wrong-synthetic-password', recoveryKey)).error).toMatch(/Could not unlock/);
    expect((await attempt(password, recoveryKey)).error).toMatch(/Could not unlock/);
    expect(await storage.get('config', 'master')).toEqual(old.envelope);
    expect(await storage.get('pending', oldRecord.mutationId)).toEqual(oldRecord);

    allowSignIn = true;
    expect((await attempt(password, recoveryKey)).error).toMatch(/unsynced changes/);
    expect(await storage.get('config', 'master')).toEqual(old.envelope);
    expect(await storage.get('pending', oldRecord.mutationId)).toEqual(oldRecord);
    await storage.delete('pending', oldRecord.mutationId);
    expect((await attempt(password, recoveryKey)).error).toBeUndefined();
    expect(await storage.get('config', 'master')).toEqual(current.envelope);
    expect(await storage.count('pending')).toBe(0);
    expect(await storage.count('revisions')).toBe(0);
    await call('session-lock', {});
    expect((await call('unlock', { password, idleMs: 300000 })).error).toBeUndefined();
    await call('session-lock', {});

    const next = createRotatedVault(current.envelope, current.root, 'replacement fixture password', bytes(), bytes(), bytes());
    await generatorHistory(current.root, current.envelope.context, { type: 'add', kind: 'password', value: 'synthetic history' });
    await recoverGeneratorHistory(current.root, current.envelope.context, next.root, next.envelope.context);
    const history = await openDB('voltura-generator-history', 2);
    const id = current.envelope.context.vaultId;
    expect(await history.get('history', id)).toBeDefined();
    await storage.put('config', next.envelope, 'master');
    await retireGeneratorHistory(next.envelope.context);
    expect(await history.get('history', id)).toBeUndefined();
    await expect(generatorHistory(current.root, current.envelope.context, { type: 'clear' })).rejects.toThrow('key changed');
    expect((await generatorHistory(next.root, next.envelope.context, { type: 'list' }))[0]?.value).toBe('synthetic history');
    history.close();
  } finally {
    vi.unstubAllGlobals();
  }
});
