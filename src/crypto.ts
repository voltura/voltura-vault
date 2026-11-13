import sodium from 'libsodium-wrappers-sumo';
import { aad, context, validateBox, validateKdf, MAX_RECORD_BYTES, VERSION, type Box, type Context, type Kdf, type MasterEnvelope, type Purpose, type Revision, type VaultKeyContext } from './format.ts';

export { sodium };
export async function ready() { await sodium.ready; }
export function wipe(bytes: Uint8Array | undefined) { if (bytes) sodium.memzero(bytes); }

export function seal(data: Uint8Array, key: Uint8Array, purpose: Purpose, c: Context): Box {
  const nonce = sodium.randombytes_buf(24);
  return { nonce, ciphertext: sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(data, aad(purpose, c), null, nonce, key) };
}
export function open(box: Box, key: Uint8Array, purpose: Purpose, c: Context, max = MAX_RECORD_BYTES): Uint8Array {
  validateBox(box, max);
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, box.ciphertext, aad(purpose, c), box.nonce, key);
}
export function derive(password: string, kdf: Kdf): Uint8Array {
  validateKdf(kdf);
  const input = sodium.from_string(password.normalize('NFC'));
  if (input.length < 1 || input.length > 1024) { wipe(input); throw Error('Use a master password between 1 and 1024 UTF-8 bytes'); }
  try { return sodium.crypto_pwhash(32, input, kdf.salt, kdf.passes, kdf.memory, sodium.crypto_pwhash_ALG_ARGON2ID13); }
  finally { wipe(input); }
}
export function wrappingKey(master: Uint8Array) { return sodium.crypto_kdf_derive_from_key(32, 1, 'VVROOT01', master); }
function accountKey(master: Uint8Array) { return sodium.crypto_kdf_derive_from_key(32, 1, 'VVAUTH01', master); }
function deriveMaster(password: string, kdf: Kdf, deviceKey?: Uint8Array) {
  if (deviceKey && deviceKey.length !== 32) throw Error('Invalid device key');
  const passwordKey = derive(password, kdf);
  if (!deviceKey) return passwordKey;
  try { return sodium.crypto_generichash(32, passwordKey, deviceKey); }
  finally { wipe(passwordKey); }
}

export function wrapDeviceKey(deviceKey: Uint8Array, recoveryKey: Uint8Array, c: Context): Box {
  if (deviceKey.length !== 32 || recoveryKey.length !== 32) throw Error('Invalid recovery material');
  const wrap = sodium.crypto_kdf_derive_from_key(32, 1, 'VVRECV01', recoveryKey);
  try { return seal(deviceKey, wrap, 'recovery-device', c); }
  finally { wipe(wrap); }
}

export function recoverDeviceKey(e: MasterEnvelope, recoveryKey: Uint8Array): Uint8Array {
  if (!e.recoveryDevice || recoveryKey.length !== 32) throw Error('Invalid recovery material');
  const wrap = sodium.crypto_kdf_derive_from_key(32, 1, 'VVRECV01', recoveryKey);
  try {
    const key = open(e.recoveryDevice, wrap, 'recovery-device', e.context, 32);
    if (key.length === 32) return key;
    wipe(key); throw Error('Invalid device key');
  } finally { wipe(wrap); }
}

export function validateNewMasterPassword(password: string) {
  if (Array.from(password.normalize('NFC')).length < 15) {
    throw Error('Use at least 15 characters for your master password.');
  }
}

export function createVault(password: string, kdf: Kdf, account?: Uint8Array,
  protection?: { deviceKey: Uint8Array; recoveryKey: Uint8Array }, c = context()): { envelope: MasterEnvelope; root: Uint8Array } {
  const master = deriveMaster(password, kdf, protection?.deviceKey), key = wrappingKey(master), root = sodium.randombytes_buf(32);
  try {
    const envelope: MasterEnvelope = { version: VERSION, context: c, kdf, root: seal(root, key, 'master-root', c) };
    if (protection) envelope.recoveryDevice = wrapDeviceKey(protection.deviceKey, protection.recoveryKey, c);
    if (account) {
      const wrap = accountKey(master);
      try { envelope.account = seal(account, wrap, 'account-token', c); }
      finally { wipe(wrap); }
    }
    return { envelope, root };
  }
  catch (e) { wipe(root); throw e; }
  finally { wipe(master); wipe(key); }
}

const identifierContexts = ['VVSRCID1', 'VVFOLD01', 'VVBWID01'] as const;
export function identifierKey(e: MasterEnvelope, root: Uint8Array, name: typeof identifierContexts[number]) {
  if (!e.identifiers) {
    if (e.context.epoch !== 1) throw Error('Missing vault identifier keys');
    return sodium.crypto_kdf_derive_from_key(32, 1, name, root);
  }
  const keys = open(e.identifiers, root, 'identifier-keys', e.context, 96);
  try {
    if (keys.length !== 96) throw Error('Invalid vault identifier keys');
    const offset = identifierContexts.indexOf(name) * 32;
    return keys.slice(offset, offset + 32);
  } finally { wipe(keys); }
}

export function createRotatedVault(old: MasterEnvelope, oldRoot: Uint8Array, password: string,
  account: Uint8Array, deviceKey: Uint8Array, recoveryKey: Uint8Array) {
  if (!old.recoveryDevice || !old.account || old.context.epoch >= 0xffffffff) throw Error('Vault cannot be rotated');
  const next = context(old.context.vaultId, old.context.objectId, old.context.epoch + 1);
  const result = createVault(password, { ...old.kdf, salt: sodium.randombytes_buf(16) }, account, { deviceKey, recoveryKey }, next);
  const identifiers = new Uint8Array(96);
  try {
    for (const [index, name] of identifierContexts.entries()) {
      const key = name === 'VVFOLD01' ? sodium.randombytes_buf(32) : identifierKey(old, oldRoot, name);
      try { identifiers.set(key, index * 32); } finally { wipe(key); }
    }
    result.envelope.identifiers = seal(identifiers, result.root, 'identifier-keys', next);
    return result;
  } catch (error) { wipe(result.root); throw error; }
  finally { wipe(identifiers); }
}
export function unlock(password: string, e: MasterEnvelope, useAccount?: (account: Uint8Array) => void, deviceKey?: Uint8Array): Uint8Array {
  if (e.version !== VERSION) throw Error('Unsupported vault version');
  if (Boolean(e.recoveryDevice) !== Boolean(deviceKey)) throw Error('This vault requires its device key.');
  const master = deriveMaster(password, e.kdf, deviceKey), key = wrappingKey(master);
  try {
    const root = open(e.root, key, 'master-root', e.context, 32);
    if (root.length !== 32) { wipe(root); throw Error('Invalid vault key'); }
    try {
      if (useAccount && e.account) {
        const wrap = accountKey(master);
        try {
          const account = open(e.account, wrap, 'account-token', e.context, 32);
          if (account.length !== 32) { wipe(account); throw Error('Invalid account credential'); }
          try { useAccount(account); } finally { wipe(account); }
        } finally { wipe(wrap); }
      }
      return root;
    } catch (error) { wipe(root); throw error; }
  } finally { wipe(master); wipe(key); }
}
export function encryptRecord(text: string, root: Uint8Array, c: Context, parents: string[]): Revision {
  const data = sodium.from_string(text);
  try { return encryptRecordBytes(data, root, c, parents, crypto.randomUUID()); }
  finally { wipe(data); }
}
function encryptRecordBytes(data: Uint8Array, root: Uint8Array, c: Context, parents: string[], mutationId: string): Revision {
  if (data.length > MAX_RECORD_BYTES) throw Error('Note exceeds 1 MB');
  const key = sodium.randombytes_buf(32);
  try { return { version: VERSION, context: c, parents, mutationId, key: seal(key, root, 'record-key', c), body: seal(data, key, 'record', c) }; }
  finally { wipe(key); }
}
export function decryptRecord(r: Revision, root: Uint8Array, expected: VaultKeyContext): string {
  const data = decryptRecordBytes(r, root, expected);
  try { return sodium.to_string(data); } finally { wipe(data); }
}
function decryptRecordBytes(r: Revision, root: Uint8Array, expected: VaultKeyContext) {
  if (r.version !== VERSION || r.context.vaultId !== expected.vaultId || r.context.epoch !== expected.epoch) throw Error('Wrong vault, format, or key epoch');
  const key = open(r.key, root, 'record-key', r.context, 32);
  try { return open(r.body, key, 'record', r.context); }
  finally { wipe(key); }
}

export function rewriteRevision(r: Revision, oldRoot: Uint8Array, active: VaultKeyContext, newRoot: Uint8Array, epoch: number) {
  if (epoch <= active.epoch) throw Error('Invalid replacement epoch');
  const data = decryptRecordBytes(r, oldRoot, active);
  try {
    const replacement = encryptRecordBytes(data, newRoot, { ...r.context, epoch }, r.parents, r.mutationId);
    const verified = decryptRecordBytes(replacement, newRoot, replacement.context);
    try {
      if (!sodium.memcmp(data, verified)) throw Error('Replacement record differs');
      return replacement;
    } finally { wipe(verified); }
  } finally { wipe(data); }
}
