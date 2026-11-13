import { decryptRecord, sodium, wipe } from './crypto';
import { SYNC_HISTORY_CHANGED, VAULT_KEY_CHANGED, type MasterEnvelope, type Revision } from './format';
import { applyFeed, db, pendingInOrder, restartSync } from './storage';
import { syncFiles, type VaultRequest } from './file-sync';

import { encodeToken, packConfig, packRevision, unpackConfig, unpackRevision } from './wire';

import { callDesktop, publicDesktop } from './desktop-channel';

export const ORIGIN = import.meta.env.VITE_VAULT_API_ORIGIN ?? 'https://vault-api.test';
export const WEB_ORIGIN = import.meta.env.VITE_VAULT_WEB_ORIGIN ?? 'https://vault-ui.test';
export const separateClient = () => {
  const url = self.location;
  return publicDesktop || ['https://tauri.localhost', WEB_ORIGIN].includes(url.origin)
    || (url.protocol === 'tauri:' && url.host === 'localhost');
};
export const syncEnabled = () => self.location.origin === ORIGIN || separateClient();
const apiUrl = (path: string) => `${ORIGIN}/api/v1/${path}`;
type WriteSigner = { challenge: string; privateKey: Uint8Array };
function storageWrite(path: string) {
  return path === 'mutations' || path === 'files'
    || /^files\/[0-9a-f-]{36}\/(delete|finish|chunks\/\d+)$/i.test(path);
}
async function request(path: string, body?: unknown, token?: Uint8Array | string, method?: 'DELETE',
  write?: WriteSigner, writePublicKey?: Uint8Array) {
  if (!syncEnabled()) throw Error('Sync requires the private Vault address');
  const headers = new Headers();
  const binary = body instanceof Uint8Array;
  const payload = binary ? Uint8Array.from(body).buffer : body === undefined ? undefined : JSON.stringify(body);
  if (body !== undefined) headers.set('Content-Type', binary ? 'application/octet-stream' : 'application/json');
  if (token) headers.set('Authorization', `Bearer ${typeof token === 'string' ? token : encodeToken(token)}`);
  if (writePublicKey) headers.set('X-Vault-Write-Key', encodeToken(writePublicKey));
  if (storageWrite(path)) {
    if (!write) throw Error('Vault server update required to sync changes. Local encrypted data is retained.');
    const bytes = typeof payload === 'string' ? sodium.from_string(payload) : payload ? new Uint8Array(payload) : new Uint8Array();
    const hash = sodium.crypto_hash_sha256(bytes);
    const message = `VolturaVault write v1\n${write.challenge}\nPOST\n/api/v1/${path}\n${encodeToken(hash)}`;
    const proof = new Uint8Array(96);
    proof.set(hash);
    proof.set(sodium.crypto_sign_detached(message, write.privateKey), hash.length);
    headers.set('X-Vault-Write-Proof', encodeToken(proof));
  }
  const verb = method ?? (body === undefined ? 'GET' : 'POST');
  if (publicDesktop) {
    const bytes = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload && new Uint8Array(payload);
    const result = await callDesktop<ArrayBuffer>({ kind: 'request', call: { path, method: verb,
      body: bytes && sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL), token: headers.get('Authorization')?.slice(7),
      writeKey: headers.get('X-Vault-Write-Key') ?? undefined, proof: headers.get('X-Vault-Write-Proof') ?? undefined,
    } });
    const status = new DataView(result).getUint16(0);
    return new Response([204, 205, 304].includes(status) ? null : result.slice(2), { status });
  }
  return fetch(apiUrl(path), {
    method: verb, headers,
    body: payload,
    credentials: separateClient() || (token && path !== 'sessions') ? 'omit' : 'same-origin', cache: 'no-store', redirect: 'error',
    signal: AbortSignal.timeout(12_000),
  });
}

export async function remoteConfig(): Promise<MasterEnvelope | undefined> {
  const response = await request('config');
  if (response.status === 404) return;
  if (!response.ok) throw Error('Vault server configuration is unavailable');
  const { vaultId, encryptedConfig, keyEpoch = 1 } = await response.json();
  return unpackConfig(encryptedConfig, vaultId, keyEpoch);
}

export async function initializeRemote(e: MasterEnvelope, account: Uint8Array, recovery: Uint8Array, setup: string) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(setup)) throw Error('Enter the server setup token');
  const response = await request('bootstrap', {
    vaultId: e.context.vaultId, accountToken: encodeToken(account), recoveryToken: encodeToken(recovery), encryptedConfig: packConfig(e),
  }, setup);
  if (!response.ok) throw Error('The server rejected vault setup. Reload to check whether setup already finished.');
}

export async function withVaultSession<T>(e: MasterEnvelope, account: Uint8Array, action: (send: VaultRequest) => Promise<T>) {
  if (!navigator.locks) throw Error('This browser cannot coordinate vault sync safely');
  return navigator.locks.request('voltura-vault-sync', async () => {
    const vaultId = e.context.vaultId;
    if (publicDesktop) {
      const local = await db();
      const [saved, bound, active] = await Promise.all([
        callDesktop<string | null>({ kind: 'profile' }),
        local.get('sync', 'desktop-server'),
        local.get('config', 'master'),
      ]);
      if (!saved || (active && (saved !== bound || active.context.vaultId !== vaultId))) {
        throw Error('This local vault is bound to a different connection. Your data has been retained.');
      }
    }
    const bearerSession = separateClient();
    await sodium.ready;
    const pair = sodium.crypto_sign_keypair();
    let session: string | undefined;
    try {
    const signedIn = await request('sessions', { vaultId, client: bearerSession ? 'native' : 'browser' }, account, undefined, undefined, pair.publicKey);
    if (signedIn.status === 401) {
      const remote = await remoteConfig().catch(() => undefined);
      if (remote && remote.context.vaultId !== vaultId) {
        throw Error('This device opened a different vault from the one on the server. Your local data is still available.');
      }
      if (remote && remote.context.epoch > e.context.epoch) {
        throw Error(VAULT_KEY_CHANGED);
      }
    }
    if (!signedIn.ok) throw Error('The vault server rejected sign-in. Your local data is still available.');
    const { token, writeChallenge } = await signedIn.json();
    if (bearerSession) {
      if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw Error('Invalid vault session');
      session = token;
    }
    try {
      const write = typeof writeChallenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(writeChallenge)
        ? { challenge: writeChallenge, privateKey: pair.privateKey } : undefined;
      return await action((path, body) => request(path, body, session, undefined, write));
    } finally {
      await request('session', undefined, session, 'DELETE').catch(() => undefined);
    }
    } finally { wipe(pair.privateKey); }
  });
}

export async function synchronize(e: MasterEnvelope, root: Uint8Array, account: Uint8Array, resumeAfterRestore = false,
  progress?: (done: number, total: number) => void) {
  return withVaultSession(e, account, async send => {
    const vaultId = e.context.vaultId;
    const key = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', root);
    try {
      const local = await db();
      let cursor = await local.get('sync', vaultId) ?? '0';
      let generation = await local.get('sync', `generation:${vaultId}`);
      const readFeed = async (from: string, expected?: string) => {
        const result = await send('changes', { cursor: from, generation: expected });
        if (result.status === 409) throw Error(SYNC_HISTORY_CHANGED);
        if (!result.ok) throw Error('Could not download encrypted changes');
        const feed = await result.json();
        if (typeof feed.generation !== 'string' || !/^[a-f0-9]{32}$/.test(feed.generation)
          || (expected !== undefined && feed.generation !== expected)
          || typeof feed.cursor !== 'string' || !/^\d{1,19}$/.test(feed.cursor) || BigInt(feed.cursor) < BigInt(from)
          || !Array.isArray(feed.revisions) || feed.revisions.length > 8 || typeof feed.more !== 'boolean'
          || (feed.revisions.length === 0 ? feed.more || feed.cursor !== from : feed.cursor === from)) throw Error('Invalid change feed');
        const revisions: Revision[] = [];
        for (const wire of feed.revisions) {
          try {
            revisions.push(unpackRevision(wire, e.context, root, key));
          } catch {
            // The server can store opaque data without the vault key. An
            // unauthenticated entry must never block unrelated valid changes.
          }
        }
        return { generation: feed.generation as string, cursor: feed.cursor as string, more: feed.more as boolean,
          revisions, rejected: revisions.length !== feed.revisions.length };
      };
      const pull = async () => {
        for (let page = 0; page < 128; page++) {
          const feed = await readFeed(cursor, generation);
          await applyFeed(vaultId, cursor, feed.cursor, feed.revisions, feed.generation, feed.rejected,
            (queued, incoming) => decryptRecord(queued, root, e.context) === decryptRecord(incoming, root, e.context));
          cursor = feed.cursor;
          generation = feed.generation;
          if (!feed.more) return;
        }
        throw Error('More encrypted changes are available. Sync again to continue.');
      };
      try {
        if (cursor !== '0' && generation === undefined) throw Error(SYNC_HISTORY_CHANGED);
        await pull();
      } catch (error) {
        if (!resumeAfterRestore || !(error instanceof Error) || error.message !== SYNC_HISTORY_CHANGED) throw error;
        const feed = await readFeed('0');
        generation = feed.generation;
        await restartSync(vaultId, feed.generation);
        cursor = '0';
        await pull();
      }
      const pending = await pendingInOrder(e.context);
      const deferredRevisions = new Set<string>();
      let uploaded = false;
      let refreshedOutbox = false;
      for (const [index, revision] of pending.entries()) {
        progress?.(index, pending.length);
        if (refreshedOutbox && !(await local.get('pending', revision.mutationId))) continue;
        if (revision.parents.some(parent => deferredRevisions.has(parent))) {
          deferredRevisions.add(revision.context.revisionId);
          continue;
        }
        const result = await send('mutations', packRevision(revision, key));
        if (result.status === 409 && await local.get('sync', `rotation-revision:${revision.context.revisionId}`)) {
          await pull();
          refreshedOutbox = true;
          if (!(await local.get('pending', revision.mutationId))) continue;
        }
        if ([400, 409, 413, 422, 507].includes(result.status)) {
          deferredRevisions.add(revision.context.revisionId);
          continue;
        }
        if (!result.ok) throw Error(`Server declined an edit (${result.status}). It remains saved on this device.`);
        uploaded = true;
      }
      progress?.(pending.length, pending.length);
      if (uploaded) await pull();
      const recoveryKey = `recovering:${vaultId}`;
      const recovering = await local.get('sync', recoveryKey) !== undefined;
      const { unavailable, rejected, quotaDeferred, deferredFiles } = await syncFiles(send, e.context, root, recovering);
      if (recovering && !rejected) await local.delete('sync', recoveryKey);
      let remainingDeferred = 0;
      for (const revision of pending) {
        if (deferredRevisions.has(revision.context.revisionId) && await local.get('pending', revision.mutationId)) {
          remainingDeferred++;
        }
      }
      return { unavailable, quotaDeferred, deferredFiles, deferredRevisions: remainingDeferred };
    } finally {
      wipe(key);
    }
  });
}
