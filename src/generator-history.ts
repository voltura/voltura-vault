import { openDB, type DBSchema } from 'idb';
import { decryptRecord, encryptRecord, rewriteRevision, sodium, wipe } from './crypto';
import { context, type Revision, type VaultKeyContext } from './format';
import { db as vaultDb } from './storage';

export type HistoryKind = 'username' | 'password' | 'passphrase';
export type HistoryEntry = { id: string; kind: HistoryKind; value: string; at: number };
export type HistoryAction = { type: 'list' } | { type: 'clear' } | { type: 'add'; kind: HistoryKind; value: string };

interface HistoryDB extends DBSchema {
  history: { key: string; value: Revision };
  epochs: { key: string; value: number };
}

const limit = 100;
const isKind = (value: unknown): value is HistoryKind =>
  value === 'username' || value === 'password' || value === 'passphrase';
const historySlot = ({ vaultId, epoch }: VaultKeyContext) => epoch === 1 ? vaultId : `${vaultId}:${epoch}`;
const openHistory = () => openDB<HistoryDB>('voltura-generator-history', 2, {
  upgrade(db, oldVersion) {
    if (oldVersion === 0) db.createObjectStore('history');
    db.createObjectStore('epochs');
  },
  blocking(_old, _next, event) { (event.target as IDBDatabase).close(); },
});

async function openLegacyHistory() {
  try {
    return await openDB<HistoryDB>('voltura-generator-history', 1, {
      upgrade(db) { db.createObjectStore('history'); },
      blocking(_old, _next, event) { (event.target as IDBDatabase).close(); },
    });
  } catch (error) {
    if (!(error instanceof DOMException) || error.name !== 'VersionError') throw error;
    return openHistory();
  }
}

export async function retireGeneratorHistory(active: VaultKeyContext) {
  const db = await openHistory();
  try {
    const tx = db.transaction(['history', 'epochs'], 'readwrite');
    void tx.done.catch(() => undefined);
    const epochs = tx.objectStore('epochs'), history = tx.objectStore('history');
    const floor = await epochs.get(active.vaultId) ?? 1;
    if (floor > active.epoch) throw Error('The vault key changed. Reopen your vault.');
    await epochs.put(active.epoch, active.vaultId);
    for (const slot of await history.getAllKeys()) {
      const [vault, epoch = '1'] = slot.split(':');
      if (vault === active.vaultId && Number(epoch) < active.epoch) await history.delete(slot);
    }
    await tx.done;
  } finally { db.close(); }
}

export async function recoverGeneratorHistory(oldRoot: Uint8Array, old: VaultKeyContext, newRoot: Uint8Array, next: VaultKeyContext) {
  const db = await openHistory();
  const previousKey = sodium.crypto_kdf_derive_from_key(32, 1, 'VVGENH01', oldRoot);
  const nextKey = sodium.crypto_kdf_derive_from_key(32, 1, 'VVGENH01', newRoot);
  try {
    const tx = db.transaction(['history', 'epochs'], 'readwrite');
    void tx.done.catch(() => undefined);
    const floor = await tx.objectStore('epochs').get(old.vaultId) ?? 1;
    if (floor > old.epoch) { await tx.done; throw Error('The vault key changed. Reopen your vault.'); }
    const history = tx.objectStore('history');
    const previous = await history.get(historySlot(old));
    if (previous) await history.put(rewriteRevision(previous, previousKey, old, nextKey, next.epoch), historySlot(next));
    await tx.done;
  } finally { wipe(previousKey); wipe(nextKey); db.close(); }
}

export async function generatorHistory(root: Uint8Array, active: VaultKeyContext, action: HistoryAction): Promise<HistoryEntry[]> {
  const local = await vaultDb();
  const current = (await local.get('config', 'master'))?.context;
  if (current?.vaultId !== active.vaultId || current.epoch !== active.epoch) {
    throw Error('The vault key changed. Reopen your vault.');
  }
  if (active.epoch > 1) await retireGeneratorHistory(active);
  const slot = historySlot(active);
  const db = active.epoch === 1 ? await openLegacyHistory() : await openHistory();
  const key = sodium.crypto_kdf_derive_from_key(32, 1, 'VVGENH01', root);
  try {
    const usesFloor = db.version > 1;
    const tx = db.transaction(usesFloor ? ['history', 'epochs'] : ['history'], 'readwrite');
    void tx.done.catch(() => undefined);
    if (usesFloor && (await tx.objectStore('epochs').get(active.vaultId) ?? 1) !== active.epoch) {
      await tx.done;
      throw Error('The vault key changed. Reopen your vault.');
    }
    const history = tx.objectStore('history');
    if (action.type === 'clear') { await history.delete(slot); await tx.done; return []; }
    const decode = (record?: Revision): HistoryEntry[] => record ? JSON.parse(decryptRecord(record, key, active)) : [];
    if (action.type === 'list') { const record = await history.get(slot); await tx.done; return decode(record); }
    if (!isKind(action.kind) || typeof action.value !== 'string' || !action.value || action.value.length > 1024) {
      throw Error('Could not save this generated value.');
    }
    const entries = decode(await history.get(slot));
    entries.unshift({ id: crypto.randomUUID(), kind: action.kind, value: action.value, at: Date.now() });
    entries.length = Math.min(entries.length, limit);
    await history.put(encryptRecord(JSON.stringify(entries), key, context(active.vaultId, undefined, active.epoch), []), slot);
    await tx.done;
    return [];
  } finally { wipe(key); db.close(); }
}
