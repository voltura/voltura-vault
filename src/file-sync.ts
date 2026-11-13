import { open, seal, sodium, wipe } from './crypto.ts';
import { CHUNK_BYTES, MAX_ATTACHMENT_BYTES, chunkKey, uuidBytes, validateBox, type Attachment, type Context, type VaultKeyContext } from './format.ts';
import { db } from './storage.ts';
import { readAttachment } from './attachments.ts';

export type VaultRequest = (path: string, body: unknown) => Promise<Response>;
type Manifest = { objectId: string; revisionId: string; size: number; manifest: string; epoch?: number };
type Deletion = { objectId: string; revisionId: string; epoch: number; proof: string };
const encode = (bytes: Uint8Array) => sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
const decode = (value: string) => sodium.from_base64(value, sodium.base64_variants.ORIGINAL);

export function safeFileName(name: string) {
  return name.replace(/[\\/:*?"<>|\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '_').slice(0, 200).trim() || 'vault-file.bin';
}

export function fileManifest(file: Attachment, name: string, root: Uint8Array, recordId?: string): string {
  if (recordId !== undefined) uuidBytes(recordId);
  const plain = sodium.from_string(JSON.stringify({
    name: safeFileName(name), header: encode(file.header),
    nonce: encode(file.key.nonce), key: encode(file.key.ciphertext), size: file.size, recordId,
  }));
  try {
    const box = seal(plain, root, 'attachment-manifest', file.context);
    const packed = new Uint8Array(24 + box.ciphertext.length);
    packed.set(box.nonce); packed.set(box.ciphertext, 24);
    return encode(packed);
  } finally { wipe(plain); }
}

function unpack(manifest: string, c: Context, expectedSize: number, root: Uint8Array) {
  if (typeof manifest !== 'string' || manifest.length > 8192) throw Error('Invalid attachment manifest');
  const bytes = decode(manifest);
  const plain = open({ nonce: bytes.slice(0, 24), ciphertext: bytes.slice(24) }, root, 'attachment-manifest', c, 4096);
  try {
    const value = JSON.parse(sodium.to_string(plain));
    if (typeof value.name !== 'string' || value.size !== expectedSize
      || !Number.isSafeInteger(value.size) || value.size < 0 || value.size > MAX_ATTACHMENT_BYTES) throw Error('Invalid attachment metadata');
    const header = decode(value.header), key = { nonce: decode(value.nonce), ciphertext: decode(value.key) };
    validateBox(key, 32);
    if (header.length !== 24 || key.ciphertext.length !== 48) throw Error('Invalid attachment keys');
    const recordId = value.recordId;
    if (recordId !== undefined) {
      if (typeof recordId !== 'string') throw Error('Invalid attachment record');
      uuidBytes(recordId);
    }
    return { name: safeFileName(value.name), header, key, recordId };
  } finally { wipe(plain); }
}

export function attachmentDetails(file: Attachment, root: Uint8Array) {
  if (!file.manifest) return { displayName: 'Attachment.bin' };
  const { name, recordId } = unpack(file.manifest, file.context, file.size, root);
  return { displayName: name, recordId };
}

export function unpackAttachment(entry: Manifest, active: VaultKeyContext, root: Uint8Array): Attachment {
  uuidBytes(entry.objectId); uuidBytes(entry.revisionId);
  if ((entry.epoch ?? 1) !== active.epoch) throw Error('Wrong attachment key epoch');
  const context = { ...active, objectId: entry.objectId, revisionId: entry.revisionId };
  const { header, key } = unpack(entry.manifest, context, entry.size, root);
  return { version: 1, context, header, key, size: entry.size,
    chunks: Math.max(1, Math.ceil(entry.size / CHUNK_BYTES)), manifest: entry.manifest, remote: true, offline: false };
}

function requireSuccess(response: Response, operation: string) {
  if (!response.ok) throw Error(`${operation} failed (${response.status}). Local encrypted files are retained.`);
}

function deletionFor({ vaultId, epoch, objectId, revisionId }: Context, root: Uint8Array): Deletion {
  const key = sodium.crypto_kdf_derive_from_key(32, 1, 'VVDEL001', root);
  try {
    const message = sodium.from_string(`Voltura Vault file deletion v1\n${vaultId}\n${epoch}\n${objectId}\n${revisionId}`);
    return { objectId, revisionId, epoch, proof: encode(sodium.crypto_auth(message, key)) };
  } finally { wipe(key); }
}

export async function eraseLocalFile(file: Attachment) {
  const d = await db(), tx = d.transaction(['attachments', 'chunks'], 'readwrite');
  void tx.done.catch(() => undefined);
  const current = await tx.objectStore('attachments').get(file.context.objectId);
  if (current && current.context.revisionId === file.context.revisionId &&
      current.context.epoch === file.context.epoch && current.context.vaultId === file.context.vaultId) {
    await tx.objectStore('attachments').delete(file.context.objectId);
    for (let i = 0; i < current.chunks; i++) await tx.objectStore('chunks').delete(chunkKey(current.context, i));
  }
  await tx.done;
}

export async function deleteVaultFile(request: VaultRequest, file: Attachment, root: Uint8Array) {
  const deletion = deletionFor(file.context, root);
  const response = await request(`files/${deletion.objectId}/delete`, deletion);
  if (response.status === 404) {
    // An older server also returns 404, including for a published file.
    const body = await response.json().catch(() => undefined);
    if (body?.error !== 'attachment_missing') throw Error('Update the vault server before deleting files.');
    if (file.remote !== false && file.remote !== undefined) throw Error('The vault server no longer has this file. Sync and try again.');
  } else {
    requireSuccess(response, 'Delete file');
  }
  await eraseLocalFile(file);
}

export async function findDeletedFiles(request: VaultRequest, files: Attachment[], root: Uint8Array,
  newer?: { epoch: number; root: Uint8Array }) {
  const deleted = new Set<string>();
  for (let i = 0; i < files.length; i += 256) {
    const batch = new Map(files.slice(i, i + 256).map(file => [file.context.objectId, file]));
    const response = await request('files/deleted', { objectIds: [...batch.keys()] });
    if (response.status === 404) return deleted; // The previous server can still sync.
    requireSuccess(response, 'Check deleted files');
    const entries: Deletion[] = await response.json();
    if (!Array.isArray(entries) || entries.length > batch.size) throw Error('Invalid deleted file list');
    for (const entry of entries) {
      const file = batch.get(entry?.objectId);
      if (!file || entry.revisionId !== file.context.revisionId) continue;
      const key = entry.epoch === file.context.epoch ? root : entry.epoch === newer?.epoch ? newer.root : undefined;
      if (key && entry.proof === deletionFor({ ...file.context, epoch: entry.epoch }, key).proof) deleted.add(entry.objectId);
    }
  }
  return deleted;
}

export async function syncFiles(request: VaultRequest, active: VaultKeyContext, root: Uint8Array, recovering = false) {
  const d = await db();
  const { vaultId, epoch } = active;
  const belongsToVault = (file: Attachment) => file.context.vaultId === vaultId && file.context.epoch === epoch;
  const localFiles = (await d.getAll('attachments')).filter(belongsToVault);
  const deleted = await findDeletedFiles(request, localFiles, root);
  for (const file of localFiles) {
    if (deleted.has(file.context.objectId)) await eraseLocalFile(file);
  }
  if (recovering) {
    const { files, invalidIds } = await listFiles(request, active, root);
    const remote = new Set(files.map(file => file.context.objectId));
    // An unauthenticated entry may be hiding an existing attachment. Keep
    // its local status until the server returns an authenticated inventory.
    for (const file of await d.getAll('attachments')) {
      if (!file.manifest || !file.remote || !belongsToVault(file)) continue;
      const id = file.context.objectId;
      if (!invalidIds.has(id) && !remote.has(id)) await d.put('attachments', { ...file, remote: false }, id);
    }
  }
  const deferred = new Set<string>(), quota = new Set<string>();
  const canDefer = (response: Response) => [400, 404, 409, 413, 422, 507].includes(response.status);
  async function uploadFile(file: Attachment, packed: string) {
    const { objectId, revisionId } = file.context;
    const readChunk = async (index: number) => {
      const encrypted = await d.get('chunks', chunkKey(file.context, index));
      if (!encrypted) throw Error('Missing local encrypted file chunk');
      return encrypted;
    };
    try {
      const manifest = unpackAttachment({ objectId, revisionId, size: file.size, manifest: packed, epoch }, active, root);
      if (manifest.chunks !== file.chunks) return 'deferred';
      await readAttachment(manifest, root, active, readChunk, async () => undefined);
    } catch { return 'deferred'; }
    const started = await request('files', { objectId, revisionId, size: file.size, manifest: packed,
      ...(epoch === 1 ? {} : { epoch }) });
    if (canDefer(started)) return started.status === 507 ? 'quota' : 'deferred';
    requireSuccess(started, 'Start file sync');
    for (let i = 0; i < file.chunks; i++) {
      const encrypted = await d.get('chunks', chunkKey(file.context, i));
      if (!encrypted || encrypted.length !== Math.min(CHUNK_BYTES, file.size - i * CHUNK_BYTES) + 17) return 'deferred';
      const chunk = await request(`files/${objectId}/chunks/${i}`, encrypted);
      if (canDefer(chunk)) return chunk.status === 507 ? 'quota' : 'deferred';
      requireSuccess(chunk, 'Upload file chunk');
    }
    const finished = await request(`files/${objectId}/finish`, {});
    if (canDefer(finished)) return finished.status === 507 ? 'quota' : 'deferred';
    requireSuccess(finished, 'Finish file sync');
    return 'uploaded';
  }
  for (const file of await d.getAll('attachments')) {
    if (!file.manifest || file.remote || file.offline === false || !belongsToVault(file)) continue;
    const result = await uploadFile(file, file.manifest);
    const { objectId } = file.context;
    if (result === 'quota') quota.add(objectId);
    else if (result === 'deferred') deferred.add(objectId);
    else await d.put('attachments', { ...file, remote: true }, objectId);
  }
  const { files, rejected } = await listFiles(request, active, root);
  for (const file of files) {
    const { objectId, revisionId } = file.context;
    if (deleted.has(objectId)) continue;
    const current = await d.get('attachments', objectId);
    if (current) {
      if (current.context.revisionId !== revisionId || current.manifest !== file.manifest || current.size !== file.size) {
        deferred.add(objectId);
        continue;
      }
      if (!current.remote) await d.put('attachments', { ...current, remote: true }, objectId);
      continue;
    }
    try {
      await d.add('attachments', file, objectId);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'ConstraintError')) throw error;
      if ((await d.get('attachments', objectId))?.manifest !== file.manifest) deferred.add(objectId);
    }
  }
  const warning = `rejected-attachments:${vaultId}`;
  if (rejected) await d.put('sync', '1', warning);
  else await d.delete('sync', warning);
  const unavailable = (await d.getAll('attachments')).filter(file =>
    belongsToVault(file) && file.offline === false && file.remote === false).length;
  return { unavailable, rejected, quotaDeferred: quota.size, deferredFiles: deferred.size };
}

async function listFiles(request: VaultRequest, active: VaultKeyContext, root: Uint8Array) {
  const response = await request('files/list', {});
  requireSuccess(response, 'List encrypted files');
  const entries: Manifest[] = await response.json();
  if (!Array.isArray(entries) || entries.length > 1024) throw Error('Invalid file list');
  const files: Attachment[] = [];
  const invalidIds = new Set<string>();
  for (const entry of entries) {
    try {
      files.push(unpackAttachment(entry, active, root));
    } catch {
      // An invalid manifest does not prevent authentication of other files.
      if (typeof entry?.objectId === 'string') invalidIds.add(entry.objectId);
    }
  }
  if (new Set(files.map(file => file.context.objectId)).size !== files.length) throw Error('Invalid file list');
  return { files, invalidIds, rejected: files.length !== entries.length };
}

export async function downloadChunk(request: VaultRequest, file: Attachment, index: number) {
  const response = await request(`files/${file.context.objectId}/read/${index}`, {});
  requireSuccess(response, 'Download encrypted file');
  const expected = Math.min(CHUNK_BYTES, file.size - index * CHUNK_BYTES) + 17;
  if (Number(response.headers.get('Content-Length')) !== expected) throw Error('Invalid encrypted file size');
  return new Uint8Array(await response.arrayBuffer());
}
