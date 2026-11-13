import { readAttachment, rewriteAttachment } from './attachments';
import { decryptRecord, rewriteRevision, sodium, wipe } from './crypto';
import { attachmentDetails, downloadChunk, fileManifest, findDeletedFiles, unpackAttachment } from './file-sync';
import { chunkKey, context, type Attachment, type MasterEnvelope, type Revision } from './format';
import { recoverGeneratorHistory, retireGeneratorHistory } from './generator-history';
import { commitDeviceRotation, db, pendingInOrder, removeUnpublishedChunks, saveAttachmentChunks } from './storage';
import { withVaultSession } from './sync';
import { unpackRevision } from './wire';

export async function recoverDeviceRotation(old: MasterEnvelope, oldRoot: Uint8Array, next: MasterEnvelope,
  newRoot: Uint8Array, account: Uint8Array, device: { id: string; key: string }) {
  if (next.context.vaultId !== old.context.vaultId || next.context.epoch <= old.context.epoch) {
    throw Error('The server has no newer key for this vault');
  }
  return withVaultSession(next, account, send => navigator.locks.request('voltura-vault-attachment-writer', async () => {
    const d = await db(), pending = await pendingInOrder(old.context);
    const localRevisions = new Map((await d.getAll('revisions')).map(revision => [revision.context.revisionId, revision]));
    for (const revision of pending) localRevisions.set(revision.context.revisionId, revision);
    const localByMutation = new Map([...localRevisions.values()].map(revision => [revision.mutationId, revision]));
    const recovered = new Map<string, Revision>();
    let cursor = '0', generation: string | undefined;
    let rejectedServerData = false;
    const syncKey = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', newRoot);
    try {
      for (let page = 0; ; page++) {
        if (page >= 131_072) throw Error('The server change feed did not finish.');
        const changes = await send('changes', { cursor, generation });
        if (!changes.ok) throw Error('Could not verify the new server vault');
        const feed = await changes.json();
        if (typeof feed.generation !== 'string' || !/^[a-f0-9]{32}$/.test(feed.generation)
          || (generation !== undefined && feed.generation !== generation) || typeof feed.more !== 'boolean'
          || typeof feed.cursor !== 'string' || !/^\d{1,19}$/.test(feed.cursor) || BigInt(feed.cursor) < BigInt(cursor)
          || !Array.isArray(feed.revisions) || feed.revisions.length > 8
          || (feed.revisions.length === 0 ? feed.more || feed.cursor !== cursor : BigInt(feed.cursor) === BigInt(cursor))) throw Error('Invalid server change feed');
        for (const wire of feed.revisions) {
          let record: Revision;
          try { record = unpackRevision(wire, next.context, newRoot, syncKey); }
          catch { rejectedServerData = true; continue; }
          const id = record.context.revisionId;
          const local = localRevisions.get(id) ?? localByMutation.get(record.mutationId);
          if (!local) continue;
          if (local.context.revisionId !== id || local.mutationId !== record.mutationId
            || local.context.objectId !== record.context.objectId || JSON.stringify(local.parents) !== JSON.stringify(record.parents)
            || decryptRecord(local, oldRoot, old.context) !== decryptRecord(record, newRoot, next.context)) {
            throw Error('An offline edit conflicts with an existing server revision');
          }
          recovered.set(id, record);
        }
        generation = feed.generation;
        cursor = feed.cursor;
        if (!feed.more) break;
      }
    }
    finally { wipe(syncKey); }
    const rewritten: Revision[] = [];
    for (const [id, revision] of localRevisions) {
      if (recovered.has(id)) continue;
      const replacement = rewriteRevision(revision, oldRoot, old.context, newRoot, next.context.epoch);
      recovered.set(id, replacement);
      rewritten.push(replacement);
    }
    const oldFiles = await d.getAll('attachments');
    const files: Attachment[] = [];
    const listing = await send('files/list', {});
    if (!listing.ok) throw Error('Could not verify the new server attachments');
    const entries = await listing.json();
    if (!Array.isArray(entries) || entries.length > 1024) throw Error('Invalid server attachment list');
    const uploaded = new Map(entries.filter(entry => typeof entry?.objectId === 'string').map(entry => [entry.objectId, entry]));
    const deleted = await findDeletedFiles(send, oldFiles, oldRoot, { epoch: next.context.epoch, root: newRoot });
    const cached = oldFiles.filter(file => file.offline !== false && !deleted.has(file.context.objectId));
    try {
      for (const file of cached) {
        if (file.context.vaultId !== old.context.vaultId || file.context.epoch !== old.context.epoch) {
          throw Error('A local attachment uses an unexpected vault key');
        }
        const { displayName, recordId } = attachmentDetails(file, oldRoot);
        const readOld = async (index: number) => {
          const chunk = await d.get('chunks', chunkKey(file.context, index));
          if (!chunk) throw Error('A saved offline attachment is missing a chunk');
          return chunk;
        };
        const existing = uploaded.get(file.context.objectId);
        if (existing) {
          let remote: Attachment | undefined;
          try {
            const candidate = unpackAttachment(existing, next.context, newRoot);
            const details = attachmentDetails(candidate, newRoot);
            if (candidate.context.revisionId === file.context.revisionId && candidate.size === file.size
              && details.displayName === displayName && details.recordId === recordId) remote = candidate;
          } catch { /* Keep the authenticated local file below. */ }
          if (remote) {
            const candidate = remote;
            const before = sodium.crypto_generichash_init(null, 32), after = sodium.crypto_generichash_init(null, 32);
            await readAttachment(file, oldRoot, old.context, readOld, async bytes => { sodium.crypto_generichash_update(before, bytes); });
            let storageError = false;
            try {
              await saveAttachmentChunks(d, candidate.context, candidate.chunks, async () => {
                await readAttachment(candidate, newRoot, next.context, async index => {
                  const chunk = await downloadChunk(send, candidate, index);
                  try { await d.put('chunks', chunk, chunkKey(candidate.context, index)); }
                  catch (error) { storageError = true; throw error; }
                  return chunk;
                }, async bytes => { sodium.crypto_generichash_update(after, bytes); });
                if (!sodium.memcmp(sodium.crypto_generichash_final(before, 32), sodium.crypto_generichash_final(after, 32))) {
                  throw Error('A recovered attachment differs from its server copy');
                }
                files.push({ ...candidate, offline: true });
              });
              continue;
            } catch (error) {
              if (storageError) throw error;
            }
          }
          rejectedServerData = true;
        }
        // Local rewrites use fresh encryption material. Use a fresh immutable
        // ID so they cannot collide with another device recovering the same file.
        const replacement = context(next.context.vaultId, undefined, next.context.epoch);
        await saveAttachmentChunks(d, replacement, file.chunks, async () => {
          const rotated = await rewriteAttachment(file, oldRoot, newRoot, replacement.epoch, readOld,
            async (index, encrypted) => { await d.put('chunks', encrypted, chunkKey(replacement, index)); }, replacement);
          files.push({ ...rotated, manifest: fileManifest(rotated, displayName, newRoot, recordId), remote: false, offline: true });
        });
      }
      await recoverGeneratorHistory(oldRoot, old.context, newRoot, next.context);
      await commitDeviceRotation(old, next, pending, [...recovered.values()], rewritten, oldFiles, files, device);
      await retireGeneratorHistory(next.context).catch(() => undefined);
      return { edits: pending.length, files: cached.length, rejectedServerData };
    } finally { await removeUnpublishedChunks().catch(() => undefined); }
  }));
}
