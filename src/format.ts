export const VERSION = 1;
export const MAX_RECORD_BYTES = 1_000_000;
export const MAX_FOLDER_NAME_LENGTH = 256;
export const CHUNK_BYTES = 1_048_576;
export const MAX_ATTACHMENT_BYTES = 100_000_000;
export const SYNC_HISTORY_CHANGED = 'Server history changed. Your local edits are saved. Choose Resume sync after confirming the server restore.';
export const VAULT_KEY_CHANGED = 'The vault key changed on the server. Recover this device in Settings to keep your offline changes.';
export const HELLO_SYNC_RECONNECT = 'Confirm your master password to reconnect sync.';
export const HELLO_SYNC_UNAVAILABLE = 'Could not reach the vault. Saved edits will sync when it reconnects.';
export type Purpose = 'master-root' | 'record-key' | 'record' | 'attachment-key' | 'attachment' | 'attachment-manifest' | 'hello-root' | 'hello-sync' | 'account-token' | 'recovery-device' | 'identifier-keys';
export interface Context { vaultId: string; epoch: number; objectId: string; revisionId: string }
export type VaultKeyContext = Pick<Context, 'vaultId' | 'epoch'>;
export interface Box { nonce: Uint8Array; ciphertext: Uint8Array }
export interface Kdf { algorithm: 'argon2id13'; memory: number; passes: number; salt: Uint8Array }
export interface MasterEnvelope { version: 1; context: Context; kdf: Kdf; root: Box; account?: Box; recoveryDevice?: Box; identifiers?: Box }
export interface HelloCredential { id: string; input: Uint8Array }
export interface HelloEnvelope extends HelloCredential { root: Box }
export interface Revision { version: 1; context: Context; parents: string[]; key: Box; body: Box; mutationId: string }
export interface Attachment {
  version: 1; context: Context; key: Box; header: Uint8Array; size: number; chunks: number;
  manifest?: string; remote?: boolean; offline?: boolean;
}
export type AttachmentView = Attachment & { displayName?: string; recordId?: string };

export function chunkKey(context: Pick<Context, 'epoch' | 'objectId'>, index: number) {
  const { epoch, objectId } = context;
  return epoch === 1 ? `${objectId}:${index}` : `${epoch}:${objectId}:${index}`;
}

export function uuidBytes(uuid: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) throw Error('Invalid object identifier');
  return Uint8Array.from(uuid.replaceAll('-', '').match(/../g)!, b => parseInt(b, 16));
}

// Restricted deterministic CBOR encoder. No maps, floats, or indefinite lengths.
export function aad(purpose: Purpose, c: Context): Uint8Array {
  if (!Number.isSafeInteger(c.epoch) || c.epoch < 1 || c.epoch > 0xffffffff) throw Error('Invalid key epoch');
  const out: number[] = [0x87];
  function head(major: number, n: number) {
    if (n < 24) out.push((major << 5) | n);
    else if (n <= 255) out.push((major << 5) | 24, n);
    else if (n <= 65535) out.push((major << 5) | 25, n >>> 8, n & 255);
    else out.push((major << 5) | 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  }
  function bytes(b: Uint8Array, major: number) { head(major, b.length); out.push(...b); }
  bytes(new TextEncoder().encode('voltura-vault'), 3);
  head(0, VERSION);
  bytes(new TextEncoder().encode(purpose), 3);
  bytes(uuidBytes(c.vaultId), 2); head(0, c.epoch);
  bytes(uuidBytes(c.objectId), 2); bytes(uuidBytes(c.revisionId), 2);
  return new Uint8Array(out);
}

export function validateKdf(k: Kdf): void {
  if (k.algorithm !== 'argon2id13' || ![64 * 1024 ** 2, 128 * 1024 ** 2].includes(k.memory)
    || !Number.isInteger(k.passes) || k.passes < 3 || k.passes > 64
    || !(k.salt instanceof Uint8Array) || k.salt.length !== 16) throw Error('Unsupported or unsafe KDF parameters');
}

export function context(vaultId: string = crypto.randomUUID(), objectId: string = crypto.randomUUID(), epoch = 1): Context {
  return { vaultId, objectId, epoch, revisionId: crypto.randomUUID() };
}

export function validateBox(box: Box, max: number) {
  if (!(box.nonce instanceof Uint8Array) || box.nonce.length !== 24 || !(box.ciphertext instanceof Uint8Array)
    || box.ciphertext.length < 16 || box.ciphertext.length > max + 16) throw Error('Invalid encrypted object');
}
