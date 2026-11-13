import 'fake-indexeddb/auto';
import { expect, it, vi } from 'vitest';
import { chunkAad, startAttachment } from '../src/attachments';
import { createVault, encryptRecord, ready, sodium } from '../src/crypto';
import { fileManifest } from '../src/file-sync';
import { context, SYNC_HISTORY_CHANGED } from '../src/format';
import { db, saveInitial, saveRevision } from '../src/storage';
import { synchronize } from '../src/sync';
import { packRevision, type WireRevision } from '../src/wire';

it('requires consent to replay local revisions after a restore and retries an interrupted recovery', async () => {
  await ready();
  vi.stubGlobal('self', { location: { origin: 'https://vault-ui.test' } });
  vi.stubGlobal('navigator', { locks: { request: async (_: string, action: () => Promise<unknown>) => action() } });
  const account = sodium.randombytes_buf(32);
  const { root, envelope } = createVault('synthetic only', {
    algorithm: 'argon2id13', memory: 64 * 1024 ** 2, passes: 3, salt: sodium.randombytes_buf(16),
  });
  const vaultId = envelope.context.vaultId;
  const record = context(vaultId);
  const first = encryptRecord('at backup time', root, record, []);
  const later = encryptRecord('synced after backup', root, { ...record, revisionId: crypto.randomUUID() }, [record.revisionId]);
  const pending = encryptRecord('pending at restore time', root, { ...record, revisionId: crypto.randomUUID() }, [later.context.revisionId]);
  const wire: { mutationId: string; revisionId: string; parents: string[] }[] = [];
  const files = new Map<string, { objectId: string; revisionId: string; size: number; manifest: string }>();
  const invalidFile = { objectId: crypto.randomUUID(), revisionId: crypto.randomUUID(), size: 0, manifest: 'invalid' };
  let publishInvalidFile = false;
  const uploaded = new Set<string>();
  const deferredFileId = crypto.randomUUID();
  let generation = 'a'.repeat(32), failMutation = false;
  const rejectedMutations = new Map<string, number>();
  let racingRevision: WireRevision | undefined;
  const conflictedFileId = '00000000-0000-4000-8000-000000000001';
  const fetchMock = vi.fn(async (url: string, request: RequestInit) => {
    const path = new URL(url).pathname.replace('/api/v1/', '');
    if (path === 'sessions') return Response.json({ token: 'a'.repeat(43), writeChallenge: 'b'.repeat(43) });
    if (path === 'session') return new Response();
    if (path === 'files/deleted') return Response.json([]);
    if (path === 'files/list') return Response.json([
      ...(publishInvalidFile ? [invalidFile] : []),
      ...[...files.values()].filter(file => uploaded.has(file.objectId)),
    ]);
    if (path.endsWith('/chunks/0')) return new Response();
    if (path.endsWith('/finish')) { uploaded.add(path.split('/')[1]); return new Response(); }
    const body = JSON.parse(String(request.body));
    if (path === 'files') {
      if (body.objectId === deferredFileId) return new Response(null, { status: 507 });
      if (body.objectId === conflictedFileId) return new Response(null, { status: 409 });
      files.set(body.objectId, body);
      return new Response();
    }
    if (path === 'changes') {
      if (body.generation && body.generation !== generation) return new Response(null, { status: 409 });
      return Response.json({ generation, cursor: String(wire.length), revisions: wire.slice(Number(body.cursor)), more: false });
    }
    if (path !== 'mutations') throw Error('Unexpected request');
    if (failMutation) return new Response(null, { status: 503 });
    if (racingRevision && racingRevision.mutationId === body.mutationId) {
      wire.push(racingRevision);
      racingRevision = undefined;
      return new Response(null, { status: 409 });
    }
    if (rejectedMutations.has(body.mutationId)) return new Response(null, { status: rejectedMutations.get(body.mutationId) });
    if (body.parents.some((parent: string) => !wire.some(entry => entry.revisionId === parent))) {
      return new Response(null, { status: 409 });
    }
    if (!wire.some(entry => entry.mutationId === body.mutationId)) wire.push(body);
    return new Response();
  });
  vi.stubGlobal('fetch', fetchMock);
  try {
    await saveInitial(envelope);
    await saveRevision(first);
    await synchronize(envelope, root, account);
    await saveRevision(later);
    await synchronize(envelope, root, account);
    await saveRevision(pending);
    const local = await db();
    for (const offline of [true, false]) {
      const { state, attachment } = startAttachment(root, context(vaultId), 0);
      const id = attachment.context.objectId;
      await local.put('attachments', { ...attachment, remote: true, offline,
        manifest: fileManifest(attachment, 'synthetic.txt', root) }, id);
      if (offline) await local.put('chunks', sodium.crypto_secretstream_xchacha20poly1305_push(
        state, new Uint8Array(), chunkAad(attachment.context, 0), sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
      ), `${id}:0`);
    }
    wire.splice(1);
    generation = 'b'.repeat(32);
    await expect(synchronize(envelope, root, account)).rejects.toThrow(SYNC_HISTORY_CHANGED);
    expect(wire.map(entry => entry.mutationId)).toEqual([first.mutationId]);
    expect(await local.get('pending', pending.mutationId)).toEqual(pending);
    const invalidRevision = { ...wire[0], revisionId: crypto.randomUUID(), mutationId: crypto.randomUUID() };
    wire.push(invalidRevision); // Changing the IDs invalidates the authenticated envelope.
    publishInvalidFile = true;
    failMutation = true;
    await expect(synchronize(envelope, root, account, true)).rejects.toThrow('503');
    expect(await local.get('pending', later.mutationId)).toEqual(later);
    failMutation = false;
    await expect(synchronize(envelope, root, account)).resolves.toEqual({
      unavailable: 1, quotaDeferred: 0, deferredFiles: 0, deferredRevisions: 0,
    });
    expect(wire.map(entry => entry.mutationId)).toEqual([first, invalidRevision, later, pending].map(revision => revision.mutationId));
    expect(await local.count('pending')).toBe(0);
    expect(await local.get('heads', record.objectId)).toEqual([pending.context.revisionId]);
    expect(await local.get('revisions', invalidRevision.revisionId)).toBeUndefined();
    expect(await local.get('attachments', invalidFile.objectId)).toBeUndefined();
    expect(await local.get('sync', `rejected-revisions:${vaultId}`)).toBe(generation);
    expect(await local.get('sync', `rejected-attachments:${vaultId}`)).toBe('1');
    expect(uploaded.size).toBe(1);
    publishInvalidFile = false;
    await synchronize(envelope, root, account);
    expect(await local.get('sync', `recovering:${vaultId}`)).toBeUndefined();
    expect(await local.get('sync', `rejected-attachments:${vaultId}`)).toBeUndefined();

    const { state: deferredState, attachment: deferred } = startAttachment(root, context(vaultId, deferredFileId), 0);
    await local.put('attachments', { ...deferred, offline: true, remote: false,
      manifest: fileManifest(deferred, 'deferred.txt', root) }, deferredFileId);
    await local.put('chunks', sodium.crypto_secretstream_xchacha20poly1305_push(
      deferredState, new Uint8Array(), chunkAad(deferred.context, 0), sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    ), `${deferredFileId}:0`);
    const { state: conflictedState, attachment: conflictedFile } = startAttachment(root, context(vaultId, conflictedFileId), 0);
    await local.put('attachments', { ...conflictedFile, offline: true, remote: false,
      manifest: fileManifest(conflictedFile, 'conflicted.txt', root) }, conflictedFileId);
    await local.put('chunks', sodium.crypto_secretstream_xchacha20poly1305_push(
      conflictedState, new Uint8Array(), chunkAad(conflictedFile.context, 0), sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    ), `${conflictedFileId}:0`);
    const corruptFileId = '00000000-0000-4000-8000-000000000002';
    const { attachment: corruptFile } = startAttachment(root, context(vaultId, corruptFileId), 0);
    await local.put('attachments', { ...corruptFile, offline: true, remote: false,
      manifest: fileManifest(corruptFile, 'corrupt-chunk.txt', root) }, corruptFileId);
    await local.put('chunks', new Uint8Array(17), `${corruptFileId}:0`);
    const { state: outgoingState, attachment: outgoing } = startAttachment(root, context(vaultId), 0);
    const outgoingId = outgoing.context.objectId;
    await local.put('attachments', { ...outgoing, offline: true, remote: false,
      manifest: fileManifest(outgoing, 'outgoing.txt', root) }, outgoingId);
    await local.put('chunks', sodium.crypto_secretstream_xchacha20poly1305_push(
      outgoingState, new Uint8Array(), chunkAad(outgoing.context, 0), sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    ), `${outgoingId}:0`);
    const { attachment: incoming } = startAttachment(root, context(vaultId), 0);
    const incomingId = incoming.context.objectId;
    files.set(incomingId, { objectId: incomingId, revisionId: incoming.context.revisionId, size: 0,
      manifest: fileManifest(incoming, 'incoming.txt', root) });
    uploaded.add(incomingId);
    const quotaParent = encryptRecord('oversized for server quota', root, context(vaultId), []);
    const quotaChild = encryptRecord('depends on rejected parent', root,
      { ...quotaParent.context, revisionId: crypto.randomUUID() }, [quotaParent.context.revisionId]);
    const conflicted = encryptRecord('revision conflict', root, context(vaultId), []);
    const independent = encryptRecord('unrelated edit still syncs', root, context(vaultId), []);
    for (const revision of [quotaParent, quotaChild, conflicted, independent]) await saveRevision(revision);
    rejectedMutations.set(quotaParent.mutationId, 507);
    rejectedMutations.set(conflicted.mutationId, 409);
    fetchMock.mockClear();
    await expect(synchronize(envelope, root, account)).resolves.toEqual({
      unavailable: 1, quotaDeferred: 1, deferredFiles: 2, deferredRevisions: 3,
    });
    const sentMutations = fetchMock.mock.calls.filter(([url]) => url.endsWith('/mutations'))
      .map(([, request]) => JSON.parse(String(request.body)).mutationId);
    const begunFiles = fetchMock.mock.calls.filter(([url]) => url.endsWith('/files'))
      .map(([, request]) => JSON.parse(String(request.body)).objectId);
    expect(sentMutations).not.toContain(quotaChild.mutationId);
    expect(begunFiles).toContain(conflictedFileId);
    expect(begunFiles).not.toContain(corruptFileId);
    for (const revision of [quotaParent, quotaChild, conflicted]) {
      expect(await local.get('pending', revision.mutationId)).toEqual(revision);
    }
    expect(await local.get('pending', independent.mutationId)).toBeUndefined();
    expect(wire.some(entry => entry.mutationId === independent.mutationId)).toBe(true);
    expect(await local.get('attachments', deferredFileId)).toMatchObject({ offline: true, remote: false });
    expect(await local.get('attachments', conflictedFileId)).toMatchObject({ offline: true, remote: false });
    expect(await local.get('attachments', corruptFileId)).toMatchObject({ offline: true, remote: false });
    expect(await local.get('attachments', outgoingId)).toMatchObject({ offline: true, remote: true });
    expect(await local.get('attachments', incomingId)).toMatchObject({ offline: false, remote: true });

    const recovered = encryptRecord('offline edit from two devices', root, context(vaultId), []);
    const otherCopy = encryptRecord('offline edit from two devices', root, recovered.context, []);
    const syncKey = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', root);
    racingRevision = packRevision({ ...otherCopy, mutationId: recovered.mutationId }, syncKey);
    sodium.memzero(syncKey);
    await saveRevision(recovered);
    await local.put('sync', '1', `rotation-revision:${recovered.context.revisionId}`);
    await expect(synchronize(envelope, root, account)).resolves.toMatchObject({ deferredRevisions: 3 });
    expect(await local.get('pending', recovered.mutationId)).toBeUndefined();
    expect(await local.get('revisions', recovered.context.revisionId)).toEqual({
      ...otherCopy, mutationId: recovered.mutationId,
    });

    const otherEpoch = encryptRecord('edit from another epoch', root, { ...context(vaultId), epoch: 2 }, []);
    await local.put('pending', otherEpoch, otherEpoch.mutationId);
    await expect(synchronize(envelope, root, account)).rejects.toThrow('An edit uses a different vault key');
    expect(await local.get('pending', otherEpoch.mutationId)).toEqual(otherEpoch);
    expect(wire.some(entry => entry.mutationId === otherEpoch.mutationId)).toBe(false);
  } finally {
    vi.unstubAllGlobals();
  }
});
