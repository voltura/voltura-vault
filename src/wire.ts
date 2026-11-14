import { decryptRecord, sodium } from './crypto.ts';
import { MAX_RECORD_BYTES, uuidBytes, validateBox, validateKdf, type Box, type MasterEnvelope, type Revision, type VaultKeyContext } from './format.ts';

const encode = (value: Uint8Array) => sodium.to_base64(value, sodium.base64_variants.ORIGINAL);
const decode = (value: string) => sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
export const encodeToken = (value: Uint8Array) => sodium.to_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
const packBox = (box: Box) => ({ nonce: encode(box.nonce), ciphertext: encode(box.ciphertext) });
const unpackBox = (box: ReturnType<typeof packBox>) => ({ nonce: decode(box.nonce), ciphertext: decode(box.ciphertext) });

export function packConfig(e: MasterEnvelope) {
  if (!e.account) throw Error('Missing encrypted account credential');
  return encode(new TextEncoder().encode(JSON.stringify({
    ...e, kdf: { ...e.kdf, salt: encode(e.kdf.salt) }, root: packBox(e.root), account: packBox(e.account),
    recoveryDevice: e.recoveryDevice && packBox(e.recoveryDevice),
    identifiers: e.identifiers && packBox(e.identifiers),
  })));
}

export function unpackConfig(encryptedConfig: unknown, vaultId: unknown, keyEpoch = 1): MasterEnvelope {
  if (typeof encryptedConfig !== 'string' || encryptedConfig.length > 88_000) throw Error('Invalid server configuration');
  const wire = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(encryptedConfig)));
  const e: MasterEnvelope = { version: wire.version, context: wire.context,
    kdf: { ...wire.kdf, salt: decode(wire.kdf.salt) }, root: unpackBox(wire.root), account: unpackBox(wire.account),
    recoveryDevice: wire.recoveryDevice === undefined ? undefined : unpackBox(wire.recoveryDevice),
    identifiers: wire.identifiers === undefined ? undefined : unpackBox(wire.identifiers) };
  if (e.version !== 1 || e.context.vaultId !== vaultId || e.context.epoch !== keyEpoch
    || !Number.isSafeInteger(keyEpoch) || keyEpoch < 1 || keyEpoch > 0xffffffff) throw Error('Invalid server vault');
  for (const id of [e.context.vaultId, e.context.objectId, e.context.revisionId]) uuidBytes(id);
  validateKdf(e.kdf); validateBox(e.root, 32); validateBox(e.account!, 32);
  if (e.recoveryDevice) validateBox(e.recoveryDevice, 32);
  if (keyEpoch > 1 && !e.identifiers) throw Error('Missing vault identifier keys');
  if (e.identifiers) validateBox(e.identifiers, 96);
  return e;
}

export type WireRevision = {
  version: 1; epoch: number; objectId: string; revisionId: string; mutationId: string; parents: string[]; envelope: string;
};

// Authenticate the ancestry and idempotency identifier along with the opaque boxes.
function macInput(r: Omit<WireRevision, 'envelope'>, vaultId: string, boxes: Uint8Array) {
  const meta = new TextEncoder().encode(JSON.stringify([r.version, vaultId, r.epoch, r.objectId, r.revisionId, r.mutationId, r.parents]));
  const bytes = new Uint8Array(meta.length + 1 + boxes.length);
  bytes.set(meta); bytes.set(boxes, meta.length + 1);
  return bytes;
}
export function packRevision(r: Revision, key: Uint8Array): WireRevision {
  const { vaultId, epoch, objectId, revisionId } = r.context;
  const meta = { version: r.version, epoch, objectId, revisionId, mutationId: r.mutationId, parents: r.parents };
  const boxes = new Uint8Array(96 + r.body.ciphertext.length);
  boxes.set(r.key.nonce); boxes.set(r.key.ciphertext, 24); boxes.set(r.body.nonce, 72); boxes.set(r.body.ciphertext, 96);
  const bytes = new Uint8Array(32 + boxes.length);
  bytes.set(sodium.crypto_auth(macInput(meta, vaultId, boxes), key)); bytes.set(boxes, 32);
  return { ...meta, envelope: encode(bytes) };
}
export function unpackRevision(wire: WireRevision, expected: VaultKeyContext, root: Uint8Array, key: Uint8Array): Revision {
  const { vaultId } = expected;
  if (wire.version !== 1 || wire.epoch !== expected.epoch || !Array.isArray(wire.parents) || wire.parents.length > 32
    || typeof wire.envelope !== 'string' || wire.envelope.length > 1_400_000) throw Error('Invalid remote revision');
  for (const id of [wire.objectId, wire.revisionId, wire.mutationId, ...wire.parents]) uuidBytes(id);
  const bytes = decode(wire.envelope), boxes = bytes.subarray(32);
  if (boxes.length < 112 || boxes.length > MAX_RECORD_BYTES + 112
    || !sodium.crypto_auth_verify(bytes.subarray(0, 32), macInput(wire, vaultId, boxes), key)) throw Error('Remote revision failed authentication');
  const r: Revision = {
    version: 1, context: { vaultId, epoch: wire.epoch, objectId: wire.objectId, revisionId: wire.revisionId },
    mutationId: wire.mutationId, parents: wire.parents,
    key: { nonce: boxes.slice(0, 24), ciphertext: boxes.slice(24, 72) },
    body: { nonce: boxes.slice(72, 96), ciphertext: boxes.slice(96) },
  };
  decryptRecord(r, root, expected);
  return r;
}
