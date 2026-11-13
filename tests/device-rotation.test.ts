import 'fake-indexeddb/auto';
import { expect, it, vi } from 'vitest';
import { chunkAad, readAttachment, startAttachment } from '../src/attachments';
import { decryptRecord, encryptRecord, ready, rewriteRevision, sodium } from '../src/crypto';
import { attachmentDetails, fileManifest } from '../src/file-sync';
import { chunkKey, context, type MasterEnvelope } from '../src/format';
import { recoverDeviceRotation } from '../src/rotation-recovery';
import { applyFeed, currentRevisions, db, saveInitial, saveRevision } from '../src/storage';
import { packRevision } from '../src/wire';

it('retains the authenticated local view, preserves a cached file, and reconciles equivalent rotated revisions', async () => {
  await ready();
  vi.stubGlobal('self', { location: { origin: 'https://vault-ui.test' } });
  vi.stubGlobal('navigator', { locks: { request: async (_: string, action: () => Promise<unknown>) => action() } });
  const oldRoot = sodium.randombytes_buf(32), newRoot = sodium.randombytes_buf(32), account = sodium.randombytes_buf(32);
  const box = { nonce: new Uint8Array(24), ciphertext: new Uint8Array(48) };
  const old: MasterEnvelope = { version: 1, context: context(), root: box,
    kdf: { algorithm: 'argon2id13', memory: 64 * 1024 ** 2, passes: 3, salt: new Uint8Array(16) } };
  const { vaultId, objectId } = old.context;
  const next = { ...old, context: context(vaultId, objectId, 2) };
  const first = encryptRecord('confirmed', oldRoot, context(vaultId), []);
  const second = encryptRecord('missing local child', oldRoot, context(vaultId, first.context.objectId), [first.context.revisionId]);
  const confirmed = rewriteRevision(first, oldRoot, old.context, newRoot, 2);
  const generation = 'a'.repeat(32);
  const syncKey = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', newRoot);
  const bytes = new Uint8Array([1, 2, 3]);
  const { state, attachment } = startAttachment(oldRoot, context(vaultId), bytes.length);
  const oldFileId = attachment.context.objectId;
  const remoteFile = startAttachment(newRoot, { ...attachment.context, epoch: 2 }, bytes.length).attachment;
  const wire = { objectId: oldFileId, revisionId: attachment.context.revisionId, epoch: 2, size: bytes.length,
    manifest: fileManifest(remoteFile, 'synthetic.bin', newRoot, first.context.objectId) };
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/sessions')) return Response.json({ token: 'a'.repeat(43), writeChallenge: 'b'.repeat(43) });
    if (path.endsWith('/session')) return new Response();
    if (path.endsWith('/changes')) return Response.json({ generation, cursor: '1', revisions: [packRevision(confirmed, syncKey)], more: false });
    if (path.endsWith('/files/list')) return Response.json([wire]);
    if (path.endsWith('/files/deleted')) return Response.json([]);
    if (path.endsWith('/read/0')) return new Response(null, { status: 503 });
    throw Error('Unexpected request');
  }));
  try {
    await saveInitial(old);
    await saveRevision(first);
    await saveRevision(second);
    const local = await db();
    await local.delete('pending', first.mutationId);
    await local.put('attachments', { ...attachment, offline: true, remote: true,
      manifest: fileManifest(attachment, 'synthetic.bin', oldRoot, first.context.objectId) }, oldFileId);
    await local.put('chunks', sodium.crypto_secretstream_xchacha20poly1305_push(
      state, bytes, chunkAad(attachment.context, 0), sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    ), chunkKey(attachment.context, 0));

    const result = await recoverDeviceRotation(old, oldRoot, next, newRoot, account, { id: 'test-device', key: 'synthetic' });
    expect(result.rejectedServerData).toBe(true);
    expect((await currentRevisions()).map(revision => decryptRecord(revision, newRoot, next.context))).toEqual(['missing local child']);
    expect(await local.get('revisions', first.context.revisionId)).toEqual(confirmed);
    expect(await local.get('pending', second.mutationId)).toBeDefined();
    const [cached] = await local.getAll('attachments');
    expect(cached.context.objectId).not.toBe(oldFileId);
    expect(cached).toMatchObject({ offline: true, remote: false });
    expect(attachmentDetails(cached, newRoot)).toEqual({ displayName: 'synthetic.bin', recordId: first.context.objectId });
    await readAttachment(cached, newRoot, next.context, async index => (await local.get('chunks', chunkKey(cached.context, index)))!,
      async clear => { expect(clear).toEqual(bytes); });

    const peer = rewriteRevision(second, oldRoot, old.context, newRoot, 2);
    const different = encryptRecord('different content', newRoot, peer.context, peer.parents);
    different.mutationId = peer.mutationId;
    const equivalent = (left: typeof peer, right: typeof peer) =>
      decryptRecord(left, newRoot, next.context) === decryptRecord(right, newRoot, next.context);
    await expect(applyFeed(vaultId, '0', '2', [confirmed, different], generation, false, equivalent)).rejects.toThrow('different data');
    expect(await local.get('pending', second.mutationId)).toBeDefined();
    await applyFeed(vaultId, '0', '2', [confirmed, peer], generation, false, equivalent);
    expect(await local.get('revisions', peer.context.revisionId)).toEqual(peer);
    expect(await local.get('pending', second.mutationId)).toBeUndefined();
    expect(await local.get('sync', `rotation-revision:${peer.context.revisionId}`)).toBeUndefined();
  } finally {
    vi.unstubAllGlobals();
  }
});
