import 'fake-indexeddb/auto';
import { beforeAll, describe, expect, it } from 'vitest';
import { applyFeed, currentRevisions, db, removeUnpublishedChunks, saveAttachmentChunks, saveImport, saveInitial, saveRevision } from '../src/storage';
import { startAttachment } from '../src/attachments';
import { createVault, encryptRecord, ready, sodium } from '../src/crypto';
import { context } from '../src/format';
beforeAll(ready);
describe('transactional encrypted edits', () => {
  it('preserves both concurrent branches with an outbox entry for every saved edit', async () => {
    const root = sodium.randombytes_buf(32), c = context(), parent = encryptRecord('base', root, c, []);
    await saveRevision(parent);
    const a = encryptRecord('branch-a', root, { ...c, revisionId: crypto.randomUUID() }, [c.revisionId]);
    const b = encryptRecord('branch-b', root, { ...c, revisionId: crypto.randomUUID() }, [c.revisionId]);
    expect(await saveRevision(a)).toBe('saved'); expect(await saveRevision(b)).toBe('conflict');
    const heads = await currentRevisions(); expect(heads.map(h => h.context.revisionId)).toEqual(expect.arrayContaining([a.context.revisionId, b.context.revisionId]));
    const d = await db(); expect(await d.count('pending')).toBe(3);
    expect(await saveRevision(a)).toBe('saved'); expect(await d.count('pending')).toBe(3);
  });
  it('refuses to overwrite an existing local vault', async () => {
    const v = createVault('synthetic', { algorithm: 'argon2id13', memory: 64 * 1024 ** 2, passes: 3, salt: sodium.randombytes_buf(16) });
    const r = encryptRecord('synthetic', v.root, context(v.envelope.context.vaultId), []);
    const initial = await db();
    const previousHeads = await initial.count('heads');
    const previousPending = await initial.count('pending');
    await saveInitial(v.envelope);
    expect(await initial.count('heads')).toBe(previousHeads);
    expect(await initial.count('pending')).toBe(previousPending);
    await saveRevision(r);
    await expect(saveInitial(v.envelope)).rejects.toThrow('already exists');
    expect(await (await db()).get('config', 'master')).toEqual(v.envelope);
    const vaultId = v.envelope.context.vaultId;
    await applyFeed(vaultId, '0', '0', [], 'a'.repeat(32));
    await expect(applyFeed(vaultId, '0', '1', [r], 'b'.repeat(32))).rejects.toThrow('server was restored');
    const d = await db();
    expect(await d.get('pending', r.mutationId)).toEqual(r);
    expect(await d.get('sync', vaultId)).toBe('0');
    const staleEntry = encryptRecord('stale import', v.root, { ...context(vaultId), epoch: 2 }, []);
    await expect(saveImport(v.envelope.context, [staleEntry])).rejects.toThrow('local vault changed');
    expect(await d.get('revisions', staleEntry.context.revisionId)).toBeUndefined();
    await d.delete('config', 'master');
  });
  it('rolls back the revision and head when its outbox insert fails', async () => {
    const root = sodium.randombytes_buf(32), c = context(), first = encryptRecord('initial', root, c, []);
    await saveRevision(first);
    const next = encryptRecord('must not save partially', root, { ...c, revisionId: crypto.randomUUID() }, [c.revisionId]);
    next.mutationId = first.mutationId; // An outbox uniqueness violation occurs after revision insertion.
    await expect(saveRevision(next)).rejects.toThrow();
    const d = await db();
    expect(await d.get('revisions', next.context.revisionId)).toBeUndefined();
    expect(await d.get('heads', c.objectId)).toEqual([c.revisionId]);
  });
  it('rejects a changed retry without overwriting the accepted revision', async () => {
    const root = sodium.randombytes_buf(32), c = context(), original = encryptRecord('accepted', root, c, []);
    await saveRevision(original);
    const changed = structuredClone(original); changed.body.ciphertext[0] ^= 1;
    await expect(saveRevision(changed)).rejects.toThrow('different data');
    const d = await db();
    expect(await d.get('revisions', c.revisionId)).toEqual(original);
    expect(await d.get('pending', original.mutationId)).toEqual(original);
  });
  it('cleans interrupted staging without deleting a published file', async () => {
    const c = context(), root = sodium.randombytes_buf(32);
    const { attachment } = startAttachment(root, c, 0);
    const d = await db(), orphan = crypto.randomUUID();
    await d.put('attachments', attachment, c.objectId);
    await d.put('chunks', new Uint8Array([1]), `${c.objectId}:0`);
    await d.put('chunks', new Uint8Array([2]), `${orphan}:0`);
    await d.put('chunks', new Uint8Array([3]), `${orphan}:1`);
    expect(await removeUnpublishedChunks()).toBe(2);
    expect(await d.get('chunks', `${c.objectId}:0`)).toEqual(new Uint8Array([1]));
    expect(await d.get('attachments', c.objectId)).toEqual(attachment);
    expect(await removeUnpublishedChunks()).toBe(0);
  });
});

it('cleans up only the partial file and explains a storage quota failure', async () => {
  const d = await db(), existing = crypto.randomUUID(), attempted = crypto.randomUUID();
  const chunk = Uint8Array.of(1, 2, 3);
  await d.put('chunks', chunk, `${existing}:0`);
  await expect(saveAttachmentChunks(d, { objectId: attempted, epoch: 1 }, 2, async () => {
    await d.put('chunks', chunk, `${attempted}:0`);
    throw new DOMException('Synthetic storage quota failure', 'QuotaExceededError');
  })).rejects.toThrow('Not enough space in this browser to save the file');
  expect(await d.get('chunks', `${attempted}:0`)).toBeUndefined();
  expect(await d.get('attachments', attempted)).toBeUndefined();
  expect(await d.get('chunks', `${existing}:0`)).toEqual(chunk);
});
