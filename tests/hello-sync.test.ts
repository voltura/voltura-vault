import 'fake-indexeddb/auto';
import { expect, it, vi } from 'vitest';
import { createVault, encryptRecord, ready, sodium } from '../src/crypto';
import { context, HELLO_SYNC_RECONNECT, HELLO_SYNC_UNAVAILABLE } from '../src/format';
import { disableHelloSync, enrollHelloSync, flushDeviceRevocations, helloKeyId, helloSyncKey, refreshHelloSync, savedHelloSync } from '../src/hello-sync';
import { db, saveInitial, saveRevision } from '../src/storage';
import { synchronize } from '../src/sync';

it('retains an offline outbox and reconnects after a lost refresh response without unlocking again', async () => {
  await ready();
  const account = sodium.randombytes_buf(32);
  const { root, envelope } = createVault('synthetic only', {
    algorithm: 'argon2id13', memory: 64 * 1024 ** 2, passes: 3, salt: sodium.randombytes_buf(16),
  });
  const hello = { id: 'synthetic', input: sodium.randombytes_buf(32) };
  const key = helloSyncKey(sodium.randombytes_buf(32), hello);
  const encoding = sodium.base64_variants.URLSAFE_NO_PADDING;
  const token = () => sodium.to_base64(sodium.randombytes_buf(32), encoding);
  const protect = vi.fn(async (bytes: Uint8Array, protect: boolean) => protect
    ? Uint8Array.from([8, ...bytes]) : bytes.subarray(1));
  const enrolled = new Map<string, string>();
  const revoked = new Set<string>();
  const wire: unknown[] = [];
  let offline = false, loseResponse = false;
  const expiry = Math.floor(Date.now() / 1000) + 30 * 86400;
  const request = vi.fn(async (url: string, options: RequestInit) => {
    if (offline) throw new TypeError('Offline');
    const path = new URL(url).pathname.split('/').slice(3);
    if (path[0] === 'sync-devices') {
      const id = path[1];
      if (options.method === 'DELETE') { revoked.add(id); enrolled.delete(id); return new Response(null, { status: 204 }); }
      if (path[2] === 'refresh' && options.headers instanceof Headers &&
          (options.headers.get('Authorization') !== `Bearer ${enrolled.get(id)}` || !options.headers.has('X-Vault-Write-Key'))) {
        return new Response(null, { status: 401 });
      }
      const refreshed = token();
      enrolled.set(id, refreshed);
      if (path[2] === 'refresh' && loseResponse) throw new TypeError('Response lost after rotation');
      return Response.json({ refreshToken: refreshed, refreshExpiresAt: expiry, token: token(), writeChallenge: token() });
    }
    if (path[0] === 'config') return new Response(null, { status: 404 });
    if (path[0] === 'changes') {
      const from = Number(JSON.parse(String(options.body)).cursor);
      return Response.json({ generation: 'a'.repeat(32), cursor: String(wire.length), revisions: wire.slice(from), more: false });
    }
    if (path[0] === 'mutations') {
      expect((options.headers as Headers).get('X-Vault-Write-Proof')).toBeTruthy();
      wire.push(JSON.parse(String(options.body))); return new Response();
    }
    if (path[0] === 'files') return Response.json([]);
    if (path[0] === 'session') return new Response();
    throw Error('Unexpected request');
  });
  vi.stubGlobal('self', { location: { origin: 'https://tauri.localhost' } });
  vi.stubGlobal('navigator', { onLine: true, locks: { request: async (_: string, action: () => Promise<unknown>) => action() } });
  vi.stubGlobal('fetch', request);
  try {
    await saveInitial(envelope);
    const local = await db();
    const unavailableProtection = async () => { throw Error('Windows protection failed'); };
    await expect(enrollHelloSync(envelope, account, key, hello.id, unavailableProtection, true))
      .rejects.toThrow('Windows protection failed');
    expect(await local.get('sync', helloKeyId(envelope))).toBeUndefined();
    expect(await savedHelloSync(envelope)).toBeUndefined();
    expect(enrolled.size).toBe(0);
    await enrollHelloSync(envelope, account, key, hello.id, protect, true);
    const saved = (await savedHelloSync(envelope))!;
    expect(await local.get('sync', helloKeyId(envelope))).toBe(hello.id);
    await expect(enrollHelloSync(envelope, account, key, hello.id, protect, true))
      .rejects.toThrow('Windows Hello is already set up.');
    expect(await savedHelloSync(envelope)).toEqual(saved);
    expect(saved.capsule).not.toContain(enrolled.get(saved.device));
    const pending = encryptRecord('saved while offline', root, context(envelope.context.vaultId), []);
    await saveRevision(pending);
    const sync = () => synchronize(envelope, root, writeKey => refreshHelloSync(envelope, key, writeKey, protect));
    offline = true;
    await expect(sync()).rejects.toThrow(HELLO_SYNC_UNAVAILABLE);
    expect(await local.get('pending', pending.mutationId)).toEqual(pending);
    offline = false; loseResponse = true;
    await expect(sync()).rejects.toThrow(HELLO_SYNC_UNAVAILABLE);
    expect(await savedHelloSync(envelope)).toEqual(saved);
    loseResponse = false;
    await expect(sync()).rejects.toThrow(HELLO_SYNC_RECONNECT);
    expect(await local.get('pending', pending.mutationId)).toEqual(pending);
    await enrollHelloSync(envelope, account, key, hello.id, protect);
    expect(revoked.has(saved.device)).toBe(true);
    const replacement = (await savedHelloSync(envelope))!;
    expect(replacement.device).not.toBe(saved.device);
    await sync();
    expect(wire).toHaveLength(1);
    expect(await local.count('pending')).toBe(0);
    offline = true;
    await disableHelloSync(envelope, key, undefined, protect);
    expect(await local.get('sync', helloKeyId(envelope))).toBeUndefined();
    expect(await savedHelloSync(envelope)).toBeUndefined();
    expect(revoked.has(replacement.device)).toBe(false);
    offline = false;
    await flushDeviceRevocations(envelope, account);
    expect(revoked.has(replacement.device)).toBe(true);
  } finally { vi.unstubAllGlobals(); }
});
