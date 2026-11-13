import { argon2idAsync } from '@noble/hashes/argon2.js';
import { sodium, wipe } from './crypto';
import { MAX_FOLDER_NAME_LENGTH, MAX_RECORD_BYTES } from './format';
import { ITEM_TYPES } from './item-editor';
import { encodeFolder } from './organization';

const MAX_EXPORT_BYTES = 32 * 1024 * 1024;
const MAX_ITEMS = 10_000;
const PREFIX = '\x1evoltura-bitwarden-v1\n';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const kinds: Partial<Record<number, string>> = ITEM_TYPES;

export type ImportedItem = { kind: string; name: string; folder: string; source: Record<string, unknown> };
export type ImportSummary = { items: number; folders: number; attachments: number; types: Record<string, number>;
  passkeys: number; archived: number; reprompt: number; unresolvedFolders: number };
type ImportBatch = { items: ImportedItem[]; folderNames: string[]; summary: ImportSummary };

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid Bitwarden JSON structure');
  return value as Record<string, unknown>;
}
function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    throw Error('Unsupported Bitwarden export key derivation settings');
  }
  return value;
}
const b64 = (value: string) => sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
const decodeJson = (text: string) => record(JSON.parse(text));
const bytes = (input: Uint8Array) => Uint8Array.from(input);

async function deriveBitwarden(password: Uint8Array, outer: Record<string, unknown>) {
  if (typeof outer.salt !== 'string' || outer.salt.length < 1 || outer.salt.length > 256) throw Error('Invalid export salt');
  const salt = encoder.encode(outer.salt);
  if (outer.kdfType === 0) {
    const iterations = integer(outer.kdfIterations, 5000, 2_000_000);
    const key = await crypto.subtle.importKey('raw', bytes(password), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
  }
  if (outer.kdfType === 1) {
    const m = integer(outer.kdfMemory, 16, 256) * 1024;
    const t = integer(outer.kdfIterations, 2, 10);
    const p = integer(outer.kdfParallelism, 1, 16);
    const hashed = new Uint8Array(await crypto.subtle.digest('SHA-256', salt));
    return argon2idAsync(password, hashed, { m, t, p, dkLen: 32, maxmem: 270 * 1024 * 1024 });
  }
  throw Error('Unsupported Bitwarden export key derivation settings');
}

async function unwrapExport(outer: Record<string, unknown>, password: string) {
  if (outer.passwordProtected !== true) throw Error('This export is account-restricted. In Bitwarden, export as Password protected JSON.');
  const secret = encoder.encode(password);
  let material: Uint8Array | undefined;
  let enc: Uint8Array<ArrayBuffer> | undefined, mac: Uint8Array<ArrayBuffer> | undefined;
  try {
    if (!secret.length || secret.length > 1024) throw Error('Enter the export password');
    material = await deriveBitwarden(secret, outer);
    const expand = await crypto.subtle.importKey('raw', bytes(material), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    enc = new Uint8Array(await crypto.subtle.sign('HMAC', expand, encoder.encode('enc\x01')));
    mac = new Uint8Array(await crypto.subtle.sign('HMAC', expand, encoder.encode('mac\x01')));
    const encKey = await crypto.subtle.importKey('raw', enc, 'AES-CBC', false, ['decrypt']);
    const macKey = await crypto.subtle.importKey('raw', mac, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const decrypt = async (value: unknown) => {
      if (typeof value !== 'string' || !value.startsWith('2.')) throw Error('Unsupported encrypted export format');
      const parts = value.slice(2).split('|');
      if (parts.length !== 3) throw Error('Malformed encrypted export');
      const [iv, cipher, tag] = parts.map(b64);
      if (iv.length !== 16 || tag.length !== 32 || cipher.length < 16 || cipher.length % 16) throw Error('Malformed encrypted export');
      const authenticated = new Uint8Array(iv.length + cipher.length);
      authenticated.set(iv); authenticated.set(cipher, iv.length);
      if (!await crypto.subtle.verify('HMAC', macKey, bytes(tag), authenticated)) throw Error('Wrong export password or damaged export');
      return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: bytes(iv) }, encKey, bytes(cipher)));
    };
    wipe(await decrypt(outer.encKeyValidation_DO_NOT_EDIT));
    const clear = await decrypt(outer.data);
    try { return decodeJson(decoder.decode(clear)); } finally { wipe(clear); }
  } finally { wipe(secret); wipe(material); wipe(enc); wipe(mac); }
}

export function encodeImported(item: ImportedItem) { return PREFIX + JSON.stringify(item); }
export function decodeImported(text: string): ImportedItem | undefined {
  if (!text.startsWith(PREFIX)) return;
  try {
    const value = record(JSON.parse(text.slice(PREFIX.length)));
    if (typeof value.kind === 'string' && typeof value.name === 'string' && typeof value.folder === 'string') {
      return { kind: value.kind, name: value.name, folder: value.folder, source: record(value.source) };
    }
  } catch { /* Older notes can contain arbitrary text. */ }
}

export async function parseBitwarden(file: Blob, password: string): Promise<ImportBatch> {
  if (file.size > MAX_EXPORT_BYTES) throw Error('Bitwarden JSON must be 32 MiB or smaller');
  let source: Record<string, unknown>;
  try { source = decodeJson(await file.text()); } catch { throw Error('Choose a valid Bitwarden JSON export'); }
  if (source.encrypted === true) source = await unwrapExport(source, password);
  if (source.encrypted === true || !Array.isArray(source.items) || source.items.length > MAX_ITEMS) throw Error('Expected a Bitwarden export with at most 10,000 items');
  if (Array.isArray(source.collections) && source.collections.length) {
    throw Error('This export contains organization collections. Voltura cannot preserve their sharing permissions.');
  }
  const folders = new Map<string, string>();
  if (source.folders !== undefined) {
    if (!Array.isArray(source.folders) || source.folders.length > MAX_ITEMS) throw Error('Invalid Bitwarden folders');
    for (const value of source.folders) {
      const f = record(value);
      if (typeof f.id !== 'string' || typeof f.name !== 'string') throw Error('Invalid Bitwarden folder');
      if (f.name.length > MAX_FOLDER_NAME_LENGTH) throw Error('A Bitwarden folder name exceeds 256 characters');
      folders.set(f.id, f.name);
    }
  }
  let attachments = 0, passkeys = 0, archived = 0, reprompt = 0, unresolvedFolders = 0;
  const folderNames = [...new Set(folders.values())];
  let encodedBytes = folderNames.filter(Boolean).reduce((total, name) =>
    total + encoder.encode(encodeFolder({ key: name, name })).byteLength, 0);
  const types: Record<string, number> = {};
  const items = source.items.map(value => {
    const entry = record(value);
    if (entry.organizationId || (Array.isArray(entry.collectionIds) && entry.collectionIds.length)) {
      throw Error('This export contains organization items. Use a personal vault export.');
    }
    if (typeof entry.data === 'string' && !entry.login && !entry.secureNote && !entry.card && !entry.identity
      && !entry.sshKey && !entry.bankAccount && !entry.driversLicense && !entry.passport) {
      throw Error('This item uses an unsupported Bitwarden data blob. Export your personal vault as password-protected JSON.');
    }
    if (typeof entry.type !== 'number' || !Number.isInteger(entry.type) || typeof entry.name !== 'string') throw Error('Invalid Bitwarden item');
    const kind = kinds[entry.type] ?? 'Other item';
    if (Array.isArray(entry.attachments)) attachments += entry.attachments.length;
    const login = entry.login;
    if (login && typeof login === 'object' && 'fido2Credentials' in login && Array.isArray(login.fido2Credentials)) {
      passkeys += login.fido2Credentials.length;
    }
    if (typeof entry.archivedDate === 'string') archived++;
    if (entry.reprompt !== undefined && entry.reprompt !== null && entry.reprompt !== 0) reprompt++;
    if (typeof entry.folderId === 'string' && !folders.has(entry.folderId)) unresolvedFolders++;
    types[kind] = (types[kind] ?? 0) + 1;
    const item = { kind, name: entry.name, folder: typeof entry.folderId === 'string' ? folders.get(entry.folderId) ?? '' : '', source: entry };
    const itemBytes = encoder.encode(encodeImported(item)).byteLength;
    if (itemBytes > MAX_RECORD_BYTES) throw Error('A Bitwarden item exceeds the 1 MB record limit');
    encodedBytes += itemBytes;
    if (encodedBytes > MAX_EXPORT_BYTES) throw Error('The imported records exceed 32 MiB after expanding folders. Split the export into smaller batches.');
    return item;
  });
  return { items, folderNames,
    summary: { items: items.length, folders: folders.size, attachments, types, passkeys, archived, reprompt, unresolvedFolders } };
}
