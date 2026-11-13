import { openDB, type DBSchema } from 'idb';
import { chunkKey, type Attachment, type Context, type MasterEnvelope, type Revision, type VaultKeyContext } from './format.ts';
interface VaultDB extends DBSchema {
  config: { key: string; value: MasterEnvelope };
  revisions: { key: string; value: Revision };
  heads: { key: string; value: string[] };
  pending: { key: string; value: Revision };
  attachments: { key: string; value: Attachment };
  chunks: { key: string; value: Uint8Array };
  sync: { key: string; value: string };
}
export const DB_NAME = 'voltura-vault-feasibility-v1';
export const db = () => openDB<VaultDB>(DB_NAME, 3, {
  upgrade(d, oldVersion) {
    if (!oldVersion) for (const name of ['config', 'revisions', 'heads', 'pending', 'attachments', 'chunks'] as const) d.createObjectStore(name);
    if (oldVersion < 2) d.createObjectStore('sync');
  },
  blocking(_old, _next, event) { (event.target as IDBDatabase).close(); },
});

function sameRevision(existing: Revision, r: Revision) {
  const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, index) => value === b[index]);
  return existing.version === r.version && existing.mutationId === r.mutationId
    && existing.context.vaultId === r.context.vaultId && existing.context.epoch === r.context.epoch
    && existing.context.objectId === r.context.objectId && existing.context.revisionId === r.context.revisionId
    && existing.parents.length === r.parents.length && existing.parents.every((value, index) => value === r.parents[index])
    && bytesEqual(existing.key.nonce, r.key.nonce) && bytesEqual(existing.key.ciphertext, r.key.ciphertext)
    && bytesEqual(existing.body.nonce, r.body.nonce) && bytesEqual(existing.body.ciphertext, r.body.ciphertext);
}
export async function saveInitial(envelope: MasterEnvelope, device?: { id: string; key: string }, server?: string) {
  const d = await db();
  const tx = d.transaction(['config', 'sync'], 'readwrite');
  void tx.done.catch(() => undefined); // Observe early aborts even when an individual request rejects first.
  if (await tx.objectStore('config').get('master')) { tx.abort(); throw Error('A vault already exists on this device'); }
  await tx.objectStore('config').add(envelope, 'master');
  if (device) await tx.objectStore('sync').put(device.key, device.id);
  if (server) await tx.objectStore('sync').put(server, 'desktop-server');
  await tx.done;
}
export async function saveRevision(r: Revision): Promise<'saved' | 'conflict'> {
  const d = await db(), tx = d.transaction(['config', 'revisions', 'heads', 'pending'], 'readwrite');
  void tx.done.catch(() => undefined);
  const active = (await tx.objectStore('config').get('master'))?.context;
  if (active && (active.vaultId !== r.context.vaultId || active.epoch !== r.context.epoch)) {
    tx.abort(); throw Error('The vault changed in another window. Reopen it before editing.');
  }
  const existing = await tx.objectStore('revisions').get(r.context.revisionId);
  if (existing) {
    if (!sameRevision(existing, r)) { tx.abort(); throw Error('Revision identifier already contains different data'); }
    await tx.done; return 'saved';
  }
  const heads = await tx.objectStore('heads').get(r.context.objectId) ?? [];
  const conflict = heads.some(h => !r.parents.includes(h));
  await tx.objectStore('revisions').add(r, r.context.revisionId);
  await tx.objectStore('pending').add(r, r.mutationId);
  await tx.objectStore('heads').put([...heads.filter(h => !r.parents.includes(h)), r.context.revisionId], r.context.objectId);
  await tx.done;
  return conflict ? 'conflict' : 'saved';
}

export async function commitDeviceRotation(old: MasterEnvelope, replacement: MasterEnvelope,
  pending: Revision[], recovered: Revision[], rewritten: Revision[], oldFiles: Attachment[], files: Attachment[], device: { id: string; key: string }) {
  const d = await db();
  const names = ['config', 'sync', 'revisions', 'heads', 'pending', 'attachments'] as const;
  const tx = d.transaction(names, 'readwrite');
  void tx.done.catch(() => undefined);
  const current = (await tx.objectStore('config').get('master'))?.context;
  const currentPending = await tx.objectStore('pending').getAll();
  const currentFiles = await tx.objectStore('attachments').getAll();
  const expectedPending = new Map(pending.map(revision => [revision.mutationId, revision]));
  const expectedFiles = new Map(oldFiles.map(file => [file.context.objectId, file]));
  if (current?.vaultId !== old.context.vaultId || current.epoch !== old.context.epoch || current.revisionId !== old.context.revisionId
    || currentPending.length !== pending.length || currentPending.some(revision => {
      const expected = expectedPending.get(revision.mutationId);
      return !expected || !sameRevision(revision, expected);
    }) || currentFiles.length !== oldFiles.length || currentFiles.some(file => {
      const expected = expectedFiles.get(file.context.objectId);
      return !expected || file.context.revisionId !== expected.context.revisionId || file.manifest !== expected.manifest
        || file.remote !== expected.remote || file.offline !== expected.offline;
    })) {
    tx.abort(); throw Error('Local edits changed in another window. Retry device recovery.');
  }
  const server = await tx.objectStore('sync').get('desktop-server');
  await Promise.all(names.map(name => tx.objectStore(name).clear()));
  if (server) await tx.objectStore('sync').put(server, 'desktop-server');
  await tx.objectStore('config').add(replacement, 'master');
  await tx.objectStore('sync').add(device.key, device.id);
  const parents = new Set(recovered.flatMap(revision => revision.parents));
  const heads = new Map<string, string[]>();
  for (const revision of recovered) {
    const { objectId, revisionId } = revision.context;
    await tx.objectStore('revisions').add(revision, revisionId);
    if (!parents.has(revisionId)) {
      const current = heads.get(objectId) ?? [];
      current.push(revisionId);
      heads.set(objectId, current);
    }
  }
  for (const [id, revisions] of heads) await tx.objectStore('heads').add(revisions, id);
  for (const revision of rewritten) {
    await tx.objectStore('pending').add(revision, revision.mutationId);
    await tx.objectStore('sync').add('1', `rotation-revision:${revision.context.revisionId}`);
  }
  for (const file of files) await tx.objectStore('attachments').add(file, file.context.objectId);
  await tx.done;
}

export async function publishAttachment(file: Attachment) {
  const d = await db();
  const tx = d.transaction(['config', 'attachments'], 'readwrite');
  void tx.done.catch(() => undefined);
  const current = (await tx.objectStore('config').get('master'))?.context;
  if (current?.vaultId !== file.context.vaultId || current.epoch !== file.context.epoch) {
    tx.abort(); throw Error('The vault changed in another window. Reopen it before adding files.');
  }
  await tx.objectStore('attachments').add(file, file.context.objectId);
  await tx.done;
}

export async function pendingInOrder(active: VaultKeyContext) {
  const d = await db();
  const waiting = new Map((await d.getAll('pending')).map(r => [r.context.revisionId, r]));
  const ordered: Revision[] = [];
  while (waiting.size) {
    const before = waiting.size;
    for (const [id, r] of waiting) {
      if (r.context.vaultId !== active.vaultId) throw Error('Pending edit belongs to another vault');
      if (r.context.epoch !== active.epoch) throw Error('An edit uses a different vault key. It is still saved on this device.');
      if (r.parents.some(p => waiting.has(p))) continue;
      ordered.push(r); waiting.delete(id);
    }
    if (waiting.size === before) throw Error('Invalid local revision ancestry');
  }
  return ordered;
}

export async function saveImport(active: VaultKeyContext, entries: Revision[], progress?: (done: number, total: number) => void) {
  const d = await db(), tx = d.transaction(['config', 'heads', 'revisions', 'pending'], 'readwrite');
  void tx.done.catch(() => undefined);
  const config = await tx.objectStore('config').get('master');
  if (config?.context.vaultId !== active.vaultId || config.context.epoch !== active.epoch || entries.some(({ context }) =>
    context.vaultId !== active.vaultId || context.epoch !== active.epoch)) {
    tx.abort();
    throw Error('The local vault changed during import');
  }
  const addedIds = new Set<string>();
  progress?.(0, entries.length);
  for (const [index, entry] of entries.entries()) {
    const { objectId, revisionId } = entry.context;
    if (await tx.objectStore('heads').getKey(objectId) === undefined) {
      await tx.objectStore('revisions').add(entry, revisionId);
      await tx.objectStore('heads').add([revisionId], objectId);
      await tx.objectStore('pending').add(entry, entry.mutationId);
      addedIds.add(objectId);
    }
    if ((index + 1) % 10 === 0 && index + 1 < entries.length) progress?.(index + 1, entries.length);
  }
  await tx.done;
  progress?.(entries.length, entries.length);
  return { added: addedIds.size, addedIds };
}

// The sync Web Lock covers this reset and the following pull. Requeueing all
// local revisions preserves parents that the restored server may have lost.
export async function restartSync(vaultId: string, generation: string) {
  const d = await db();
  const tx = d.transaction(['config', 'sync', 'revisions', 'pending'], 'readwrite');
  void tx.done.catch(() => undefined);
  if ((await tx.objectStore('config').get('master'))?.context.vaultId !== vaultId) {
    tx.abort();
    throw Error('The local vault changed during sync');
  }
  let cursor = await tx.objectStore('revisions').openCursor();
  while (cursor) {
    const revision = cursor.value;
    if (revision.context.vaultId === vaultId) await tx.objectStore('pending').put(revision, revision.mutationId);
    cursor = await cursor.continue();
  }
  await tx.objectStore('sync').put('0', vaultId);
  await tx.objectStore('sync').put(generation, `generation:${vaultId}`);
  await tx.objectStore('sync').put(generation, `recovering:${vaultId}`);
  await tx.objectStore('sync').delete(`rejected-revisions:${vaultId}`);
  await tx.done;
}

export async function applyFeed(vaultId: string, previous: string, next: string, revisions: Revision[], generation: string, rejected = false,
  equivalentRecoveryRevision?: (local: Revision, incoming: Revision) => boolean) {
  const d = await db(), tx = d.transaction(['config', 'sync', 'revisions', 'heads', 'pending'], 'readwrite');
  void tx.done.catch(() => undefined);
  const fail = (message: string): never => { tx.abort(); throw Error(message); };
  const e = await tx.objectStore('config').get('master');
  if (e?.context.vaultId !== vaultId) fail('The local vault changed during sync');
  if ((await tx.objectStore('sync').get(vaultId) ?? '0') !== previous) fail('Another window updated the change feed');
  const generationKey = `generation:${vaultId}`;
  const localGeneration = await tx.objectStore('sync').get(generationKey);
  if (localGeneration !== undefined && localGeneration !== generation) fail('The server was restored. Changes are still saved on this device.');
  const records = tx.objectStore('revisions'), heads = tx.objectStore('heads');
  for (const r of revisions) {
    const { objectId, revisionId } = r.context;
    if (r.context.vaultId !== vaultId) fail('The change belongs to another vault');
    const existing = await records.get(revisionId);
    const queued = await tx.objectStore('pending').get(r.mutationId);
    const rotationKey = `rotation-revision:${revisionId}`;
    if (queued && !sameRevision(queued, r)) {
      const sameIdentity = queued.version === r.version && queued.mutationId === r.mutationId
        && queued.context.vaultId === vaultId && queued.context.epoch === r.context.epoch
        && queued.context.objectId === objectId && queued.context.revisionId === revisionId
        && queued.parents.length === r.parents.length && queued.parents.every((parent, index) => parent === r.parents[index]);
      let equivalent = false;
      if (sameIdentity && existing && sameRevision(queued, existing) && equivalentRecoveryRevision
        && await tx.objectStore('sync').get(rotationKey)) {
        try { equivalent = equivalentRecoveryRevision(queued, r); }
        catch { /* Fail closed if either version cannot be authenticated. */ }
      }
      if (!equivalent) fail('Server returned different data for a queued revision');
      await records.put(r, revisionId);
      await tx.objectStore('pending').delete(r.mutationId);
      await tx.objectStore('sync').delete(rotationKey);
      continue;
    }
    if (queued) await tx.objectStore('pending').delete(r.mutationId);
    if (queued) await tx.objectStore('sync').delete(rotationKey);
    if (existing) {
      if (!sameRevision(existing, r)) fail('Server returned different data for an existing revision');
      continue;
    }
    for (const id of r.parents) {
      const parent = await records.get(id);
      if (parent?.context.objectId !== objectId || parent?.context.vaultId !== vaultId) fail('Server returned a revision without its parent');
    }
    const current = await heads.get(objectId) ?? [];
    await records.add(r, revisionId);
    await heads.put([...current.filter(id => !r.parents.includes(id)), revisionId], objectId);
  }
  await tx.objectStore('sync').put(next, vaultId);
  await tx.objectStore('sync').put(generation, generationKey);
  if (rejected) await tx.objectStore('sync').put(generation, `rejected-revisions:${vaultId}`);
  await tx.done;
}

// Caller must hold the origin-wide attachment-writer Web Lock. Published files
// are immutable; only chunks without a published metadata entry are staging.
// Only use for a new file or a file without a complete offline copy.
export async function saveAttachmentChunks(d: Awaited<ReturnType<typeof db>>, context: Pick<Context, 'epoch' | 'objectId'>, chunks: number, write: () => Promise<void>) {
  try {
    await write();
  } catch (error) {
    try {
      const tx = d.transaction('chunks', 'readwrite');
      void tx.done.catch(() => undefined);
      for (let index = 0; index < chunks; index++) await tx.store.delete(chunkKey(context, index));
      await tx.done;
    } catch {
      // A failed cleanup must not obscure the original error. Partial chunks
      // are never marked available and can be overwritten by a successful retry.
    }
    if (error instanceof Error && error.name === 'QuotaExceededError') {
      throw Error('Not enough space in this browser to save the file. Free up space and try again.');
    }
    throw error;
  }
}

export async function removeUnpublishedChunks() {
  const d = await db(), tx = d.transaction(['attachments', 'chunks'], 'readwrite');
  void tx.done.catch(() => undefined);
  const published = new Set((await tx.objectStore('attachments').getAll()).map(file => chunkKey(file.context, 0).slice(0, -1)));
  let cursor = await tx.objectStore('chunks').openCursor();
  let removed = 0;
  while (cursor) {
    const prefix = cursor.key.slice(0, cursor.key.lastIndexOf(':') + 1);
    if (!published.has(prefix)) { await cursor.delete(); removed++; }
    cursor = await cursor.continue();
  }
  await tx.done;
  return removed;
}
export async function currentRevisions() {
  const d = await db(), heads = await d.getAll('heads');
  return Promise.all(heads.flat().map(async id => {
    const r = await d.get('revisions', id);
    if (!r) throw Error('Missing local revision');
    return r;
  }));
}
