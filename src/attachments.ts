import { sodium, seal, open, wipe } from './crypto.ts';
import { aad, CHUNK_BYTES, MAX_ATTACHMENT_BYTES, VERSION, type Attachment, type Context, type VaultKeyContext } from './format.ts';
export function chunkAad(c: Context, index: number) {
  const prefix = aad('attachment', c), out = new Uint8Array(prefix.length + 8);
  out.set(prefix); new DataView(out.buffer).setBigUint64(prefix.length, BigInt(index), false); return out;
}
export function startAttachment(root: Uint8Array, c: Context, size: number) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ATTACHMENT_BYTES) throw Error('Attachment exceeds 100 MB');
  const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  try {
    const stream = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    return { state: stream.state, attachment: {
      version: VERSION, context: c, size, chunks: Math.max(1, Math.ceil(size / CHUNK_BYTES)),
      header: stream.header, key: seal(key, root, 'attachment-key', c),
    } satisfies Attachment };
  } finally { wipe(key); }
}
export class AttachmentAuthenticationError extends Error {}

export async function readAttachment(a: Attachment, root: Uint8Array, context: VaultKeyContext, read: (index: number) => Promise<Uint8Array>, emit: (bytes: Uint8Array) => Promise<void>) {
  if (a.version !== VERSION || a.context.vaultId !== context.vaultId || a.context.epoch !== context.epoch || !Number.isSafeInteger(a.size) || a.size < 0 || a.size > MAX_ATTACHMENT_BYTES
    || a.chunks !== Math.max(1, Math.ceil(a.size / CHUNK_BYTES)) || a.header.length !== 24) throw Error('Invalid attachment metadata');
  let key: Uint8Array;
  try { key = open(a.key, root, 'attachment-key', a.context, 32); }
  catch { throw new AttachmentAuthenticationError('Attachment key failed authentication'); }
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(a.header, key); wipe(key);
  for (let i = 0; i < a.chunks; i++) {
    const expected = Math.min(CHUNK_BYTES, a.size - i * CHUNK_BYTES), ciphertext = await read(i);
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== expected + 17) throw Error('Missing or invalid attachment chunk');
    let result;
    try { result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, ciphertext, chunkAad(a.context, i)); }
    catch { throw new AttachmentAuthenticationError('Attachment authentication failed'); }
    if (!result) throw new AttachmentAuthenticationError('Attachment authentication failed');
    try {
      const tag = i === a.chunks - 1 ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      if (result.tag !== tag || result.message.length !== expected) throw new AttachmentAuthenticationError('Truncated or reordered attachment');
      await emit(result.message);
    } finally { wipe(result.message); }
  }
}

export async function rewriteAttachment(a: Attachment, oldRoot: Uint8Array, newRoot: Uint8Array, epoch: number,
  read: (index: number) => Promise<Uint8Array>, write: (index: number, encrypted: Uint8Array, plain: Uint8Array) => Promise<void>,
  replacement = { ...a.context, epoch }) {
  if (epoch <= a.context.epoch) throw Error('Invalid replacement attachment epoch');
  if (replacement.epoch !== epoch || replacement.vaultId !== a.context.vaultId) throw Error('Invalid replacement attachment context');
  const context = replacement;
  const { attachment, state } = startAttachment(newRoot, context, a.size);
  let index = 0;
  await readAttachment(a, oldRoot, a.context, read, async plain => {
    const tag = index === a.chunks - 1 ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const encrypted = sodium.crypto_secretstream_xchacha20poly1305_push(state, plain, chunkAad(context, index), tag);
    await write(index++, encrypted, plain);
  });
  return attachment;
}
