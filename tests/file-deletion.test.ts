import 'fake-indexeddb/auto';
import { expect, it } from 'vitest';
import { startAttachment } from '../src/attachments';
import { ready, sodium } from '../src/crypto';
import { deleteVaultFile, fileManifest, syncFiles, type VaultRequest } from '../src/file-sync';
import { chunkKey, context } from '../src/format';
import { db } from '../src/storage';

it('retains offline files on failed or forged deletion and cleans them up on authenticated sync', async () => {
  await ready();
  const root = sodium.randombytes_buf(32);
  const c = context(crypto.randomUUID());
  const { attachment } = startAttachment(root, c, 0);
  const file = { ...attachment, offline: true, remote: true, manifest: fileManifest(attachment, 'fake.txt', root) };
  const d = await db();
  const cache = async () => {
    await d.put('attachments', file, c.objectId);
    await d.put('chunks', Uint8Array.of(1), chunkKey(c, 0));
  };
  await cache();
  await expect(deleteVaultFile(async () => new Response(null, { status: 503 }), file, root)).rejects.toThrow('Delete file failed');
  expect(await d.get('attachments', c.objectId)).toBeDefined();

  let proof: Record<string, unknown> = {};
  await deleteVaultFile(async (path, body) => {
    expect(path).toBe(`files/${c.objectId}/delete`);
    proof = body as Record<string, unknown>;
    return new Response(null, { status: 204 });
  }, file, root);
  expect(await d.get('attachments', c.objectId)).toBeUndefined();
  expect(await d.get('chunks', chunkKey(c, 0))).toBeUndefined();

  // Another device still has the file cached.
  await cache();
  let confirmed = false;
  const request: VaultRequest = async path => {
    if (path === 'files/deleted') return Response.json([confirmed ? proof : { ...proof, proof: 'forged' }]);
    if (path === 'files/list') return Response.json([]);
    throw Error('A deleted file must not be uploaded during restore recovery');
  };
  await syncFiles(request, c, root);
  expect(await d.get('attachments', c.objectId)).toBeDefined();
  confirmed = true;
  await syncFiles(request, c, root, true);
  expect(await d.get('attachments', c.objectId)).toBeUndefined();
  expect(await d.get('chunks', chunkKey(c, 0))).toBeUndefined();
});
