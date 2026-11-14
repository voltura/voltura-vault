import { open, seal, sodium, wipe } from './crypto';
import { HELLO_SYNC_RECONNECT, HELLO_SYNC_UNAVAILABLE, VAULT_KEY_CHANGED, type HelloCredential, type MasterEnvelope } from './format';
import { parseKey } from './recovery-key';
import { db } from './storage';
import { deviceSyncRequest, remoteConfig } from './sync';

export type ProtectCapsule = (bytes: Uint8Array, protect: boolean) => Promise<Uint8Array>;
type Saved = { device: string; expires: number; capsule: string };
type Refreshed = { refreshToken: string; refreshExpiresAt: number };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64 = () => sodium.base64_variants.URLSAFE_NO_PADDING;
const encode = (bytes: Uint8Array) => sodium.to_base64(bytes, B64());
const decode = (encoded: string) => sodium.from_base64(encoded, B64());
const suffix = ({ context: c }: MasterEnvelope) => `${c.vaultId}:${c.epoch}:${c.revisionId}`;
export const helloKeyId = (e: MasterEnvelope) => `hello:${suffix(e)}`;
const capsuleId = (e: MasterEnvelope) => `hello-sync:${suffix(e)}`;
const pendingPrefix = (e: MasterEnvelope) => `hello-sync-revoke:${e.context.vaultId}:${e.context.epoch}:`;

export function helloSyncKey(secret: Uint8Array, hello: HelloCredential) {
  const base = sodium.crypto_kdf_derive_from_key(32, 1, 'VVHSYNC1', secret);
  try { return sodium.crypto_generichash(32, `${hello.id}:${encode(hello.input)}`, base); }
  finally { wipe(base); }
}

function sameEnvelope(a: MasterEnvelope | undefined, b: MasterEnvelope) {
  return a && suffix(a) === suffix(b);
}

export async function savedHelloSync(e: MasterEnvelope): Promise<Saved | undefined> {
  const value = await (await db()).get('sync', capsuleId(e));
  if (!value || value.length > 6000) return;
  try {
    const { device, expires, capsule } = JSON.parse(value);
    if (typeof device === 'string' && UUID.test(device) && Number.isSafeInteger(expires) && expires > 0
        && typeof capsule === 'string' && /^[a-z0-9_-]{1,5462}$/i.test(capsule)) return { device, expires, capsule };
  } catch { /* Invalid storage requires reconnecting. */ }
}

async function tokenFrom(saved: Saved, e: MasterEnvelope, key: Uint8Array, dpapi: ProtectCapsule) {
  const bytes = await dpapi(decode(saved.capsule), false);
  if (bytes.length !== 72) throw Error(HELLO_SYNC_RECONNECT);
  const token = open({ nonce: bytes.subarray(0, 24), ciphertext: bytes.subarray(24) }, key, 'hello-sync', e.context, 32);
  if (token.length === 32) return token;
  wipe(token);
  throw Error(HELLO_SYNC_RECONNECT);
}

async function saveToken(e: MasterEnvelope, device: string, next: Refreshed, key: Uint8Array, dpapi: ProtectCapsule,
  hello: string, newEnrollment = false, replacedDevice?: string) {
  if (!Number.isSafeInteger(next.refreshExpiresAt) || next.refreshExpiresAt <= 0 || typeof next.refreshToken !== 'string') {
    throw Error(HELLO_SYNC_RECONNECT);
  }
  const token = parseKey(next.refreshToken);
  const bytes = new Uint8Array(72);
  try {
    const box = seal(token, key, 'hello-sync', e.context);
    bytes.set(box.nonce); bytes.set(box.ciphertext, 24);
  } finally { wipe(token); }
  const capsule = encode(await dpapi(bytes, true));
  const local = await db(), tx = local.transaction(['config', 'sync'], 'readwrite');
  void tx.done.catch(() => undefined);
  const store = tx.objectStore('sync');
  if (!sameEnvelope(await tx.objectStore('config').get('master'), e)
      || await store.get(helloKeyId(e)) !== (newEnrollment ? undefined : hello)) {
    tx.abort(); throw Error('Windows Hello changed. Reopen the vault and try again.');
  }
  if (newEnrollment) await store.add(hello, helloKeyId(e));
  if (replacedDevice) await store.put('1', pendingPrefix(e) + replacedDevice);
  await store.put(JSON.stringify({ device, expires: next.refreshExpiresAt, capsule }), capsuleId(e));
  await store.delete(pendingPrefix(e) + device);
  await tx.done;
}

export async function flushDeviceRevocations(e: MasterEnvelope, account: Uint8Array) {
  const local = await db(), prefix = pendingPrefix(e);
  const pending = await local.getAllKeys('sync', IDBKeyRange.bound(prefix, `${prefix}\uffff`));
  for (const key of pending) {
    const device = key.slice(prefix.length);
    if (!UUID.test(device)) continue;
    const response = await deviceSyncRequest(device, e, account, 'revoke').catch(() => undefined);
    if (response?.ok) await local.delete('sync', key);
    else break;
  }
}

async function detachSync(e: MasterEnvelope, removeHello = false) {
  const local = await db(), saved = await savedHelloSync(e);
  const tx = local.transaction('sync', 'readwrite');
  void tx.done.catch(() => undefined);
  if (saved) await tx.store.put('1', pendingPrefix(e) + saved.device);
  await tx.store.delete(capsuleId(e));
  if (removeHello) await tx.store.delete(helloKeyId(e));
  await tx.done;
  return saved;
}

export async function disableHelloSync(e: MasterEnvelope, key: Uint8Array | undefined, account: Uint8Array | undefined, dpapi: ProtectCapsule) {
  const saved = await detachSync(e, true);
  if (account) return flushDeviceRevocations(e, account);
  if (!saved || !key) return;
  let token: Uint8Array | undefined;
  try {
    token = await tokenFrom(saved, e, key, dpapi);
    if ((await deviceSyncRequest(saved.device, e, token, 'revoke')).ok) {
      await (await db()).delete('sync', pendingPrefix(e) + saved.device);
    }
  } catch { /* The ID remains queued for the next authenticated connection. */ }
  finally { wipe(token); }
}

export async function enrollHelloSync(e: MasterEnvelope, account: Uint8Array, key: Uint8Array, hello: string,
  dpapi: ProtectCapsule, newEnrollment = false) {
  const local = await db();
  if (newEnrollment && await local.get('sync', helloKeyId(e)) !== undefined) {
    throw Error('Windows Hello is already set up.');
  }
  // Persist the ID first so even an enrollment whose response is lost can be revoked.
  const previous = await savedHelloSync(e);
  await flushDeviceRevocations(e, account);
  const device = crypto.randomUUID();
  await local.put('sync', '1', pendingPrefix(e) + device);
  try {
    let response: Response;
    try { response = await deviceSyncRequest(device, e, account, 'enroll'); }
    catch { throw Error(HELLO_SYNC_UNAVAILABLE); }
    if (response.status === 404 || response.status === 405) throw Error('The vault server needs an update to support Hello sync.');
    if (!response.ok) {
      if (response.status === 401) await checkVault(e);
      throw Error('Could not enable Hello sync. Try again.');
    }
    await saveToken(e, device, await response.json(), key, dpapi, hello, newEnrollment, previous?.device);
    if (previous) await flushDeviceRevocations(e, account);
  } catch (error) {
    if (navigator.onLine) await flushDeviceRevocations(e, account);
    throw error;
  }
}

async function checkVault(e: MasterEnvelope) {
  const remote = await remoteConfig().catch(() => undefined);
  if (remote && remote.context.vaultId !== e.context.vaultId) {
    throw Error('This device opened a different vault from the one on the server. Your local data is still available.');
  }
  if (remote && remote.context.epoch > e.context.epoch) throw Error(VAULT_KEY_CHANGED);
}

export async function refreshHelloSync(e: MasterEnvelope, key: Uint8Array, writeKey: Uint8Array, dpapi: ProtectCapsule) {
  const local = await db();
  const hello = await local.get('sync', helloKeyId(e)), saved = await savedHelloSync(e);
  if (!hello || !saved) throw Error(HELLO_SYNC_RECONNECT);
  const token = await tokenFrom(saved, e, key, dpapi).catch(() => { throw Error(HELLO_SYNC_RECONNECT); });
  try {
    let response: Response;
    try { response = await deviceSyncRequest(saved.device, e, token, 'refresh', writeKey); }
    catch { throw Error(HELLO_SYNC_UNAVAILABLE); }
    if (response.status === 401) {
      await checkVault(e);
      throw Error(HELLO_SYNC_RECONNECT);
    }
    if (response.status === 404 || response.status === 405) throw Error('The vault server needs an update to support Hello sync.');
    if (!response.ok) throw Error(HELLO_SYNC_UNAVAILABLE);
    try {
      const next = await response.json() as Refreshed & { token?: string; writeChallenge?: string };
      if (!/^[A-Za-z0-9_-]{43}$/.test(next.token ?? '') || !/^[A-Za-z0-9_-]{43}$/.test(next.writeChallenge ?? '')) throw Error(HELLO_SYNC_RECONNECT);
      await saveToken(e, saved.device, next, key, dpapi, hello);
      return Response.json({ token: next.token, writeChallenge: next.writeChallenge });
    } catch {
      // The server may already have rotated. A used token can revoke its own device.
      await deviceSyncRequest(saved.device, e, token, 'revoke').catch(() => undefined);
      throw Error(HELLO_SYNC_RECONNECT);
    }
  } finally { wipe(token); }
}
