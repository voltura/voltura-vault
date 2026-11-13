/// <reference lib="webworker" />
import { createVault, decryptRecord, derive, encryptRecord, identifierKey, open, ready, recoverDeviceKey, seal, sodium, unlock, validateNewMasterPassword, wipe } from './crypto';
import { CHUNK_BYTES, chunkKey, context, MAX_FOLDER_NAME_LENGTH, type HelloCredential, type HelloEnvelope, type Kdf, type MasterEnvelope, type Revision } from './format';
import { currentRevisions, db, publishAttachment, removeUnpublishedChunks, saveAttachmentChunks, saveImport, saveInitial, saveRevision } from './storage';
import { chunkAad, readAttachment, startAttachment } from './attachments';
import { calibrate, type Calibration } from './calibration';
import { initializeRemote, remoteConfig, separateClient, syncEnabled, synchronize, withVaultSession } from './sync';
import { attachmentDetails, deleteVaultFile, downloadChunk, eraseLocalFile, fileManifest, type VaultRequest } from './file-sync';
import { decodeImported, encodeImported, parseBitwarden, type ImportedItem } from './bitwarden';
import { itemDraft, itemType, ITEM_TYPES, makeItem, reviseItem, type ItemDraft, type ItemType } from './item-editor';
import { generatorHistory, retireGeneratorHistory, type HistoryAction } from './generator-history';
import { parseKey, parseRecoveryText, recoveryText } from './recovery-key';
import { recoverDeviceRotation } from './rotation-recovery';
import { decodeFolder, encodeFolder, TRASH_MARKER, vaultFolders, type Folder, type VaultRecord } from './organization';

let root: Uint8Array | undefined, envelope: MasterEnvelope | undefined;
let account: Uint8Array | undefined;
let pendingRecoveryDigest: Uint8Array | undefined;
let importPlan: { items: Revision[]; folders: Revision[] } | undefined;
let calibration: Calibration | undefined;
let helloEnrollment: { token: string; expires: number } | undefined;
let sessionTimeout = 0, sessionExpires = 0, sessionObserved = 0;
let expiryTimer: ReturnType<typeof setTimeout> | undefined;
let sessionView: { page: string; objectId?: string } = { page: 'vault' };
function unlocked(): Uint8Array { if (!root || !envelope) throw Error('Unlock your vault first.'); return root; }
function newRevisionContext(objectId?: string) {
  const { vaultId, epoch } = envelope!.context;
  return context(vaultId, objectId, epoch);
}
const helloKeyId = ({ context }: MasterEnvelope) => `hello:${context.vaultId}:${context.epoch}:${context.revisionId}`;

const deviceKeyId = ({ context }: MasterEnvelope) => `device:${context.vaultId}:${context.epoch}:${context.revisionId}`;
const keyEncoding = () => sodium.base64_variants.URLSAFE_NO_PADDING;
async function readDeviceKey(e: MasterEnvelope) {
  if (!e.recoveryDevice) return;
  const value = await (await db()).get('sync', deviceKeyId(e));
  if (value === undefined) return;
  return parseKey(value);
}

function canImport() {
  return Boolean(root && account && envelope?.recoveryDevice && separateClient());
}

async function readRecoveryFile(file: unknown): Promise<Uint8Array> {
  if (!(file instanceof Blob) || file.size > 128) throw Error('Choose your Voltura Vault recovery key file.');
  return parseRecoveryText(await file.text());
}

async function confirmPassword(password: string, e: MasterEnvelope) {
  const deviceKey = await readDeviceKey(e);
  try { return unlock(password, e, undefined, deviceKey); }
  finally { wipe(deviceKey); }
}

function readHello(value: string | undefined): HelloEnvelope | undefined {
  if (!value || value.length > 1800) return;
  try {
    const { id, input, nonce, ciphertext } = JSON.parse(value);
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,1366}$/.test(id)) return;
    const bytes = sodium.from_base64(input);
    const root = { nonce: sodium.from_base64(nonce), ciphertext: sodium.from_base64(ciphertext) };
    if (bytes.length === 32 && root.nonce.length === 24 && root.ciphertext.length === 48) return { id, input: bytes, root };
  } catch { return; }
}

function helloWrappingKey(secret: unknown) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw Error('Windows Hello could not unlock this vault.');
  try { return sodium.crypto_kdf_derive_from_key(32, 1, 'VVHELLO1', secret); }
  finally { wipe(secret); }
}
function clearSession() {
  clearTimeout(expiryTimer);
  wipe(root); wipe(account); wipe(pendingRecoveryDigest);
  pendingRecoveryDigest = undefined;
  root = account = undefined; envelope = undefined; importPlan = undefined; calibration = undefined;
  helloEnrollment = undefined;
  sessionTimeout = sessionExpires = sessionObserved = 0;
  sessionView = { page: 'vault' };
}
function checkSession(now = Date.now()) {
  if (!sessionTimeout) return;
  if (now < sessionObserved || now >= sessionExpires) clearSession();
  else sessionObserved = now;
}
function touchSession(now = Date.now()) {
  if (!root || !sessionTimeout) return;
  sessionObserved = now;
  sessionExpires = now + sessionTimeout;
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(() => { void enqueue(() => checkSession()); }, sessionTimeout);
}
function startSession(timeout: unknown) {
  const ms = Number(timeout);
  if (!Number.isSafeInteger(ms) || ms < 60_000 || ms > 60 * 60_000) return;
  sessionTimeout = ms;
  touchSession();
}
function sourceKeyId() {
  const key = identifierKey(envelope!, unlocked(), 'VVSRCID1');
  try { return importedObjectId('Voltura source backup key', key); }
  finally { wipe(key); }
}
async function notes(): Promise<VaultRecord[]> {
  const internal = sourceKeyId();
  const d = await db(), key = unlocked(), active = envelope!.context;
  return Promise.all((await currentRevisions()).filter(r => r.context.objectId !== internal).map(async revision => {
    let text = decryptRecord(revision, key, active);
    const folderEntry = decodeFolder(text);
    if (folderEntry) return { revision, text: '', folderEntry };
    const trashed = text === TRASH_MARKER && revision.parents.length === 1;
    if (trashed) {
      const original = await d.get('revisions', revision.parents[0]);
      if (!original || original.context.objectId !== revision.context.objectId) throw Error('Missing original item in Trash');
      text = decryptRecord(original, key, envelope!.context);
    }
    const item = decodeImported(text);
    const note = item ? item.source.type === 2 && typeof item.source.notes === 'string' ? item.source.notes : '' : text;
    return { revision, text: note, item, trashed };
  }));
}

function folderRevision(folder: Folder, parents: string[] = [], existingId?: string) {
  const key = unlocked(), idKey = identifierKey(envelope!, key, 'VVFOLD01');
  try {
    const id = existingId ?? importedObjectId(folder.key, idKey);
    return encryptRecord(encodeFolder(folder), key, newRevisionContext(id), parents);
  } finally { wipe(idKey); }
}

function importedObjectId(identity: string, key: Uint8Array) {
  const input = sodium.from_string(identity);
  try {
    const digest = sodium.crypto_generichash(16, input, key);
    digest[6] = (digest[6] & 15) | 128;
    digest[8] = (digest[8] & 63) | 128;
    const hex = sodium.to_hex(digest);
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
  } finally { wipe(input); }
}

async function handle(type: string, payload: Record<string, unknown>, progress: (text: string) => void,
  steps: (done: number, total: number) => void): Promise<unknown> {
  await ready();
  checkSession();
  switch (type) {
    case 'generator-history': {
      if (!navigator.locks) throw Error('This browser cannot coordinate generator history.');
      return navigator.locks.request('voltura-vault-attachment-writer',
        () => generatorHistory(unlocked(), envelope!.context, payload as HistoryAction));
    }
    case 'session-lock': clearSession(); return;
    case 'session-touch': touchSession(); return;
    case 'session-view': {
      if (root) sessionView = { page: String(payload.page), objectId: typeof payload.objectId === 'string' ? payload.objectId : undefined };
      return;
    }
    case 'session-resume': {
      if (!root || !sessionTimeout) return;
      const result = await notes();
      checkSession();
      if (root) return { notes: result, lastInteraction: sessionExpires - sessionTimeout, ...sessionView };
      return;
    }
    case 'status': {
      const d = await db(), local = await d.get('config', 'master');
      let remote: 'local' | 'new' | 'configured' | 'unavailable' = local?.account ? 'configured' : 'local';
      let remoteEnvelope: MasterEnvelope | undefined;
      if (syncEnabled() && !local) {
        try {
          remoteEnvelope = await remoteConfig();
          remote = remoteEnvelope ? 'configured' : 'new';
        }
        catch { remote = 'unavailable'; }
      }
      const files = root ? await d.getAll('attachments') : [];
      const pending = root ? await d.count('pending') : 0;
      const rejectedServerData = !!(root && local &&
        (await d.get('sync', `rejected-revisions:${local.context.vaultId}`) ||
          await d.get('sync', `rejected-attachments:${local.context.vaultId}`)));
      const savedHello = local && readHello(await d.get('sync', helloKeyId(local)));
      checkSession();
      const key = root;
      const attachments = key ? files.map(file => ({ ...file, ...attachmentDetails(file, key) })) : [];
      const requiresRecoveryFile = Boolean(remoteEnvelope?.recoveryDevice ||
        (local?.recoveryDevice && !await d.get('sync', deviceKeyId(local))));
      return { remote, requiresRecoveryFile,
        importAvailable: canImport(), exists: !!local || remote === 'configured', pending: key ? pending : 0, attachments,
        rejectedServerData: !!key && rejectedServerData,
        hello: savedHello ? { id: savedHello.id, input: savedHello.input } : undefined,
        helloOnly: !!(key && envelope?.account && !account) };
    }
    case 'hello-confirm': {
      unlocked();
      helloEnrollment = undefined;
      let verified: Uint8Array;
      try { verified = await confirmPassword(String(payload.password), envelope!); }
      catch { throw Error('The master password is incorrect.'); }
      try {
        checkSession();
        if (!sodium.memcmp(unlocked(), verified)) throw Error('Unlock the vault with your master password first.');
        const token = crypto.randomUUID();
        helloEnrollment = { token, expires: Date.now() + 135_000 };
        return token;
      } finally { wipe(verified); }
    }
    case 'hello-enroll': {
      const wrappingKey = helloWrappingKey(payload.secret);
      const confirmation = helloEnrollment;
      helloEnrollment = undefined;
      try {
        unlocked();
        const e = envelope!;
        if (!confirmation || confirmation.token !== payload.token || confirmation.expires < Date.now()) {
          throw Error('Confirm your master password again to finish Windows Hello setup.');
        }
        const credential = payload.credential as HelloCredential;
        if (!credential || !/^[A-Za-z0-9_-]{1,1366}$/.test(credential.id)
            || !(credential.input instanceof Uint8Array) || credential.input.length !== 32) throw Error('Invalid Windows Hello passkey.');
        const d = await db();
        checkSession();
        const box = seal(unlocked(), wrappingKey, 'hello-root', e.context);
        await d.put('sync', JSON.stringify({
          id: credential.id, input: sodium.to_base64(credential.input),
          nonce: sodium.to_base64(box.nonce), ciphertext: sodium.to_base64(box.ciphertext),
        }), helloKeyId(e));
      } finally { wipe(wrappingKey); }
      return;
    }
    case 'hello-disable': {
      unlocked();
      const id = helloKeyId(envelope!);
      await (await db()).delete('sync', id);
      return;
    }
    case 'hello-unlock': {
      const wrappingKey = helloWrappingKey(payload.secret);
      if (root) {
        wipe(wrappingKey);
        throw Error('Lock the vault first.');
      }
      try {
        const d = await db(), e = await d.get('config', 'master');
        const saved = e && readHello(await d.get('sync', helloKeyId(e)));
        if (!e || !saved || saved.id !== payload.id) throw Error('Windows Hello is no longer set up.');
        root = open(saved.root, wrappingKey, 'hello-root', e.context, 32);
        if (root.length !== 32) throw Error('Invalid vault key.');
        envelope = e;
        if (e.context.epoch > 1) await retireGeneratorHistory(e.context).catch(() => undefined);
        startSession(payload.idleMs);
        return await notes();
      } catch {
        clearSession();
        throw Error('Windows Hello could not unlock the vault. Use your master password.');
      } finally { wipe(wrappingKey); }
    }
    case 'calibrate': {
      calibration = undefined;
      const salt = sodium.randombytes_buf(16);
      calibration = calibrate(passes => {
        const start = performance.now();
        const key = derive('Voltura Vault password calibration', { algorithm: 'argon2id13', memory: 128 * 1024 ** 2, salt, passes });
        wipe(key); return performance.now() - start;
      }, salt, (passes, ms) => progress(`Argon2id: ${passes} passes, ${ms} ms`));
      return calibration;
    }
    case 'make-recovery-file': {
      if (root || await (await db()).get('config', 'master')) throw Error('A vault already exists on this device.');
      const key = sodium.randombytes_buf(32);
      try {
        wipe(pendingRecoveryDigest);
        pendingRecoveryDigest = sodium.crypto_generichash(32, key, null);
        return new Blob([recoveryText(key)], { type: 'text/plain' });
      } finally { wipe(key); }
    }
    case 'create': {
      if (root) throw Error('Lock your vault before creating another one.');
      const password = String(payload.password);
      validateNewMasterPassword(password);
      if (!calibration?.targetReached) throw Error('Calibration has not reached the target on this device. Run calibration again.');
      const kdf: Kdf = calibration.kdf;
      // A fresh salt even if a calibration result is reused.
      const token = syncEnabled() ? sodium.randombytes_buf(32) : undefined;
      let recoveryKey: Uint8Array | undefined, deviceKey: Uint8Array | undefined;
      try {
        recoveryKey = await readRecoveryFile(payload.recoveryFile);
        const digest = sodium.crypto_generichash(32, recoveryKey, null);
        try {
          if (!pendingRecoveryDigest || !sodium.memcmp(digest, pendingRecoveryDigest)) {
            throw Error('Select the recovery key file you just downloaded.');
          }
        } finally { wipe(digest); }
        deviceKey = sodium.randombytes_buf(32);
        const result = createVault(password, { ...kdf, salt: sodium.randombytes_buf(16) }, token, { deviceKey, recoveryKey });
        try {
          if (token) {
            const recovery = sodium.randombytes_buf(32);
            try { await initializeRemote(result.envelope, token, recovery, String(payload.setup ?? '')); }
            finally { wipe(recovery); }
          }
          await saveInitial(result.envelope, {
            id: deviceKeyId(result.envelope), key: sodium.to_base64(deviceKey, keyEncoding()),
          });
          wipe(pendingRecoveryDigest); pendingRecoveryDigest = undefined;
          root = result.root; envelope = result.envelope;
          account = token?.slice();
          startSession(payload.idleMs);
          return await notes();
        } catch (error) { wipe(result.root); wipe(account); root = account = undefined; envelope = undefined; throw error; }
      } finally { wipe(token); wipe(recoveryKey); wipe(deviceKey); }
    }
    case 'unlock': {
      const d = await db(), local = await d.get('config', 'master');
      const replacingLegacyVault = Boolean(payload.recoveryFile && local && !local.recoveryDevice && separateClient());
      const e = !replacingLegacyVault && local ? local : syncEnabled() ? await remoteConfig() : undefined;
      if (!e) throw Error('Connect to the protected vault before recovering.');
      if (payload.recoveryFile && !e.recoveryDevice) throw Error('The connected vault does not support a recovery key.');
      clearSession();
      let deviceKey: Uint8Array | undefined, recoveryKey: Uint8Array | undefined;
      let unsyncedLegacyData = false;
      try {
        if (e.recoveryDevice && payload.recoveryFile) {
          recoveryKey = await readRecoveryFile(payload.recoveryFile);
          deviceKey = recoverDeviceKey(e, recoveryKey);
        } else {
          deviceKey = await readDeviceKey(e);
        }
        root = unlock(String(payload.password), e, token => { account = token.slice(); }, deviceKey);
        if (replacingLegacyVault) {
          if (!account) throw Error('The protected vault is missing its account credential.');
          await withVaultSession(e, account, async () => undefined);
        }
        if (!local || recoveryKey) {
          const names = ['config', 'sync', 'revisions', 'heads', 'pending', 'attachments', 'chunks'] as const;
          const tx = d.transaction(names, 'readwrite');
          void tx.done.catch(() => undefined);
          const saved = await tx.objectStore('config').get('master');
          if (saved && deviceKeyId(saved) !== deviceKeyId(local ?? e)) {
            tx.abort(); throw Error('Local vault changed. Reload and try again.');
          }
          if (replacingLegacyVault && saved) {
            if (saved.recoveryDevice) { tx.abort(); throw Error('Another protected vault is already enrolled.'); }
            const [pending, attachments] = await Promise.all([
              tx.objectStore('pending').count(), tx.objectStore('attachments').getAll(),
            ]);
            if (pending || attachments.some(file => !file.remote)) {
              unsyncedLegacyData = true;
              tx.abort();
              throw Error('Local changes would be lost.');
            }
            await Promise.all(names.map(name => tx.objectStore(name).clear()));
          }
          if (!saved || replacingLegacyVault) await tx.objectStore('config').put(e, 'master');
          if (deviceKey) await tx.objectStore('sync').put(sodium.to_base64(deviceKey, keyEncoding()), deviceKeyId(e));
          await tx.done;
        }
        envelope = e;
        if (e.context.epoch > 1) await retireGeneratorHistory(e.context).catch(() => undefined);
        startSession(payload.idleMs); return await notes();
      } catch {
        clearSession();
        if (unsyncedLegacyData) throw Error('This device has unsynced changes in a different vault. Use a separate browser profile to recover without losing them.');
        throw Error(e.recoveryDevice ? 'Could not unlock. Check the password and, if requested, the recovery key file.'
          : 'Could not unlock. Check your master password and recovery file, if used.');
      } finally { wipe(deviceKey); wipe(recoveryKey); }
    }
    case 'save': {
      const prior = payload.revision as Revision;
      if (prior.context.vaultId !== envelope?.context.vaultId) throw Error('Wrong vault');
      const original = await (await db()).get('revisions', prior.context.revisionId);
      if (!original || original.context.objectId !== prior.context.objectId) throw Error('The item changed. Sync and reopen it.');
      const clear = decryptRecord(original, unlocked(), envelope!.context);
      const c = { ...original.context, revisionId: crypto.randomUUID() };
      if (clear === TRASH_MARKER || decodeFolder(clear)) throw Error('This item cannot be edited here');
      const item = decodeImported(clear);
      const text = String(payload.text);
      const storedItem = item ?? (text === TRASH_MARKER || decodeFolder(text) ? makeItem(2) : undefined);
      const updated = reviseItem(storedItem, (payload.editor ?? itemDraft(item, text)) as ItemDraft, text);
      const revised = updated ? encodeImported(updated) : text;
      const parents = Array.isArray(payload.resolve) ? payload.resolve as string[] : [prior.context.revisionId];
      if (Array.isArray(payload.resolve)) {
        const heads = (await currentRevisions()).filter(r => r.context.objectId === c.objectId);
        if (parents.length > 32 || parents.length !== heads.length
          || !heads.every(r => parents.includes(r.context.revisionId))) throw Error('Versions changed. Sync and review them before resolving.');
      }
      const revision = encryptRecord(revised, unlocked(), c, parents);
      const status = await saveRevision(revision);
      return { status, notes: await notes() };
    }
    case 'new-note': {
      const key = unlocked();
      const type = Number(payload.itemType ?? 2) as ItemType;
      if (!Object.hasOwn(ITEM_TYPES, type)) throw Error('Unsupported item type');
      const c = newRevisionContext();
      const template = payload.item as ImportedItem | undefined;
      const item = template && itemType(template) === type ? template : makeItem(type);
      const editor = payload.editor as ItemDraft;
      if (!editor?.name?.trim()) throw Error('Enter an item name');
      const revised = reviseItem(item, editor, String(payload.text ?? ''))!;
      delete revised.source.passwordHistory;
      if (revised.folder && !vaultFolders(await notes()).some(entry => entry.key === revised.folder)) throw Error('Folder is unavailable');
      await saveRevision(encryptRecord(encodeImported(revised), key, c, []));
      return { notes: await notes(), objectId: c.objectId };
    }
    case 'folder-save':
    case 'folder-delete': {
      const previous = typeof payload.key === 'string' ? payload.key : undefined;
      const records = await notes(), folders = vaultFolders(records);
      const existing = folders.find(folder => folder.key === previous);
      const deleted = type === 'folder-delete';
      if ((previous || deleted) && !existing) throw Error('Folder is unavailable');
      const name = deleted ? existing!.name : String(payload.name ?? '').trim();
      if (!deleted && (!name || name.length > MAX_FOLDER_NAME_LENGTH)) throw Error('Enter a folder name of 1 to 256 characters');
      if (!deleted && folders.some(folder => folder.key !== previous && folder.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
        throw Error('A folder with that name already exists');
      }
      const key = previous ?? crypto.randomUUID();
      const definitions = records.filter(record => record.folderEntry?.key === key);
      const folder: Folder = deleted ? { key, name, deleted: true } : { key, name };
      const parentsByObject = new Map<string, string[]>();
      for (const { revision } of definitions) {
        const { objectId, revisionId } = revision.context;
        const parents = parentsByObject.get(objectId) ?? [];
        parents.push(revisionId);
        parentsByObject.set(objectId, parents);
      }
      if (parentsByObject.size) {
        for (const [objectId, parents] of parentsByObject) await saveRevision(folderRevision(folder, parents, objectId));
      } else if (!(await saveImport(envelope!.context, [folderRevision(folder)])).added) {
        throw Error('The folder changed. Sync and try again.');
      }
      return notes();
    }
    case 'trash-item':
    case 'restore-item': {
      const key = unlocked(), id = String(payload.revisionId);
      const current = (await currentRevisions()).find(revision => revision.context.revisionId === id);
      if (!current || current.context.objectId === sourceKeyId()) throw Error('The item changed. Sync and reopen it.');
      const clear = decryptRecord(current, key, envelope!.context);
      if (decodeFolder(clear)) throw Error('This action applies to vault items');
      let text = TRASH_MARKER;
      if (type === 'restore-item') {
        if (clear !== TRASH_MARKER || current.parents.length !== 1) throw Error('The item is not in Trash');
        const original = await (await db()).get('revisions', current.parents[0]);
        if (!original || original.context.objectId !== current.context.objectId) throw Error('Missing original item in Trash');
        text = decryptRecord(original, key, envelope!.context);
      } else if (clear === TRASH_MARKER) throw Error('The item is already in Trash');
      const c = { ...current.context, revisionId: crypto.randomUUID() };
      const status = await saveRevision(encryptRecord(text, key, c, [id]));
      return { status, notes: await notes() };
    }
    case 'reload': return notes();
    case 'import-preview': {
      importPlan = undefined;
      if (!canImport()) throw Error('Unlock a protected vault in the installed app or the independent web client before importing.');
      const key = unlocked();
      if (!(payload.file instanceof File)) throw Error('Choose a Bitwarden JSON file');
      const { items, folderNames, summary } = await parseBitwarden(payload.file, String(payload.password ?? ''));
      if (summary.reprompt > 0) {
        throw Error('This export contains items that require Bitwarden password re-prompt. Keep those items in Bitwarden until Vault supports that protection.');
      }
      const idKey = identifierKey(envelope!, key, 'VVBWID01');
      const contentIdKey = sodium.crypto_kdf_derive_from_key(32, 1, 'VVBWCT01', key);
      const existing = new Map<string, Revision[]>();
      for (const revision of await currentRevisions()) {
        const id = revision.context.objectId;
        existing.set(id, [...(existing.get(id) ?? []), revision]);
      }
      try {
        const entries: Revision[] = [];
        const withoutSourceId = new Set<string>();
        for (const revisions of existing.values()) {
          for (const revision of revisions) {
            const text = decryptRecord(revision, key, envelope!.context);
            const prior = decodeImported(text);
            if (prior && !prior.source.id) withoutSourceId.add(text);
          }
        }
        let changed = 0, duplicates = 0;
        for (const item of items) {
          const text = encodeImported(item);
          const sourceId = typeof item.source.id === 'string' && item.source.id;
          if (!sourceId && withoutSourceId.has(text)) { duplicates++; continue; }
          const id = sourceId ? importedObjectId(`id:${sourceId}`, idKey) : importedObjectId(text, contentIdKey);
          if (!sourceId) withoutSourceId.add(text);
          const prior = existing.get(id);
          if (prior) {
            if (prior.length === 1 && decryptRecord(prior[0], key, envelope!.context) === text) duplicates++;
            else changed++;
            continue;
          }
          const revision = encryptRecord(text, key, newRevisionContext(id), []);
          existing.set(id, [revision]);
          entries.push(revision);
        }
        const knownFolderKeys = new Set((await notes()).flatMap(record => record.folderEntry ? [record.folderEntry.key] : []));
        const folders = folderNames.filter(name => name && !knownFolderKeys.has(name)).map(name => folderRevision({ key: name, name }))
          .filter(revision => !existing.has(revision.context.objectId));
        importPlan = { items: entries, folders };
        return { ...summary, newItems: entries.length, newFolders: folders.length, duplicates, changed };
      } finally { wipe(idKey); wipe(contentIdKey); }
    }
    case 'import-cancel': importPlan = undefined; return;
    case 'import-commit': {
      if (!canImport()) throw Error('Unlock a protected vault in the installed app or the independent web client before importing.');
      if (!importPlan) throw Error('Preview the import first');
      const { items, folders } = importPlan;
      // Check the cached profile against the server's credentials and sync
      // generation before committing the export locally.
      await synchronize(envelope!, unlocked(), account!);
      checkSession();
      if (!canImport()) throw Error('Unlock the vault and preview the import again.');
      const result = await saveImport(envelope!.context, [...items, ...folders], steps);
      const added = items.filter(item => result.addedIds.has(item.context.objectId)).length;
      importPlan = undefined;
      return { added, skipped: items.length - added, foldersAdded: result.added - added, notes: await notes() };
    }
    case 'sync': {
      if (!account || !envelope) throw Error('This vault is stored on this device');
      const result = await synchronize(envelope, unlocked(), account, payload.resumeAfterRestore === true, payload.importProgress === true ? steps : undefined);
      return { ...result, notes: await notes() };
    }
    case 'recover-rotation': {
      if (!account || !envelope?.recoveryDevice) throw Error('Unlock with the previous master password first.');
      const old = envelope, oldRoot = unlocked(), next = await remoteConfig();
      if (!next?.recoveryDevice || next.context.vaultId !== old.context.vaultId || next.context.epoch <= old.context.epoch) {
        throw Error('The server has no newer key for this vault.');
      }
      const recovery = await readRecoveryFile(payload.recoveryFile);
      let device: Uint8Array | undefined, replacementRoot: Uint8Array | undefined, replacementAccount: Uint8Array | undefined;
      try {
        try {
          device = recoverDeviceKey(next, recovery);
          replacementRoot = unlock(String(payload.password ?? ''), next, token => { replacementAccount = token.slice(); }, device);
        } catch { throw Error('Check the new master password and recovery file.'); }
        if (!replacementAccount) throw Error('The new vault lacks an account credential.');
        const result = await recoverDeviceRotation(old, oldRoot, next, replacementRoot, replacementAccount,
          { id: deviceKeyId(next), key: sodium.to_base64(device, keyEncoding()) });
        clearSession();
        envelope = next;
        root = replacementRoot;
        account = replacementAccount;
        replacementRoot = replacementAccount = undefined;
        startSession(payload.idleMs);
        return result;
      } finally { wipe(recovery); wipe(device); wipe(replacementRoot); wipe(replacementAccount); }
    }
    case 'source-list': {
      if (!account || !envelope) throw Error('Connect to your Vault to see source versions');
      return withVaultSession(envelope, account, async send => {
        const response = await send(payload.recovery === true ? 'recovery-kits/list' : 'source-archives/list', {});
        if (!response.ok) throw Error('Could not list Vault archives');
        const body: unknown = await response.json();
        if (!Array.isArray(body) || body.length > 512 || body.some(entry =>
          !entry || typeof entry.id !== 'string' || !/^[a-f0-9-]{36}$/.test(entry.id)
          || !Number.isSafeInteger(entry.created) || entry.created < 0
          || !Number.isSafeInteger(entry.size) || entry.size < 1)) throw Error('Invalid Vault archive list.');
        return body.map(({ id, created, size }) => ({ id, created, size }));
      });
    }
    case 'source-enroll': {
      const key = unlocked(), e = envelope!, password = String(payload.password ?? '');
      wipe(await confirmPassword(password, e));
      const id = sourceKeyId(), existing = (await currentRevisions()).filter(r => r.context.objectId === id);
      if (e.context.epoch === 1 && existing.length > 1) throw Error('Source key has conflicting versions. Resolve the key before making more archives.');
      const seed = e.context.epoch > 1
        ? sodium.crypto_kdf_derive_from_key(32, 1, 'VVSRCV02', key)
        : existing.length
          ? sodium.from_base64(decryptRecord(existing[0], key, e.context), sodium.base64_variants.URLSAFE_NO_PADDING)
          : sodium.randombytes_buf(32);
      if (seed.length !== 32) { wipe(seed); throw Error('Invalid source recovery key'); }
      const pair = sodium.crypto_box_seed_keypair(seed);
      const kdf = { ...e.kdf, salt: sodium.randombytes_buf(16) };
      const wrap = derive(password, kdf), nonce = sodium.randombytes_buf(24);
      const encode = (data: Uint8Array) => sodium.to_base64(data, sodium.base64_variants.URLSAFE_NO_PADDING);
      try {
        const recoveryAad = sodium.from_string('voltura-source-recovery-v1');
        const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(seed, recoveryAad, null, nonce, wrap);
        if (e.context.epoch === 1 && !existing.length) {
          const entry = encryptRecord(encode(seed), key, newRevisionContext(id), []);
          if (!(await saveImport(e.context, [entry])).added) throw Error('Source key was set up in another window. Reopen setup.');
        }
        return {
          publicKey: encode(pair.publicKey),
          recovery: JSON.stringify({ version: 1, algorithm: kdf.algorithm, memory: kdf.memory, passes: kdf.passes,
            salt: encode(kdf.salt), nonce: encode(nonce), ciphertext: encode(sealed) }),
        };
      } finally { wipe(seed); wipe(pair.privateKey); wipe(wrap); }
    }
    case 'source-download': {
      if (!account || !envelope) throw Error('Connect to your Vault to download a source version');
      const id = String(payload.id), size = Number(payload.size);
      const recovery = payload.recovery === true;
      if (!/^[0-9a-f-]{36}$/.test(id) || !Number.isSafeInteger(size) ||
          size < (recovery ? 53 : 109) || size > (recovery ? CHUNK_BYTES + 53 : 65 * CHUNK_BYTES)) {
        throw Error('Invalid Vault archive');
      }
      return withVaultSession(envelope, account, async send => {
        const chunks: BlobPart[] = [];
        for (let offset = 0; offset < size; offset += CHUNK_BYTES) {
          const response = await send(`${recovery ? 'recovery-kits' : 'source-archives'}/${id}/${offset / CHUNK_BYTES}`, {});
          if (!response.ok || Number(response.headers.get('Content-Length')) !== Math.min(CHUNK_BYTES, size - offset)) {
            throw Error('Source version download failed');
          }
          chunks.push(await response.arrayBuffer());
        }
        return new Blob(chunks, { type: 'application/octet-stream' });
      });
    }
    case 'attachment-create': {
      if (!navigator.locks) throw Error('This browser cannot coordinate safe attachment writes. No file was created.');
      return navigator.locks.request('voltura-vault-attachment-writer', async () => {
        await removeUnpublishedChunks();
        const source = payload.file;
        if (!(source instanceof File)) throw Error('Choose a file to attach.');
        const recordId = typeof payload.recordId === 'string' ? payload.recordId : undefined;
        if (recordId !== undefined && (!(await notes()).some(record =>
          !record.trashed && !record.folderEntry && record.revision.context.objectId === recordId))) {
          throw Error('Save or restore the item before attaching files.');
        }
        const key = unlocked(), c = newRevisionContext(), size = source.size;
        const { state, attachment } = startAttachment(key, c, size), d = await db();
        const file = { ...attachment, offline: true, manifest: fileManifest(attachment, source.name, key, recordId) };
        // Staging uses unique immutable IDs. Metadata is published only after all chunks succeed.
        await saveAttachmentChunks(d, c, attachment.chunks, async () => {
          for (let i = 0; i < attachment.chunks; i++) {
            const offset = i * CHUNK_BYTES;
            const bytes = new Uint8Array(await source.slice(offset, offset + CHUNK_BYTES).arrayBuffer());
            const tag = i === attachment.chunks - 1 ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
            const encrypted = sodium.crypto_secretstream_xchacha20poly1305_push(state, bytes, chunkAad(c, i), tag); wipe(bytes);
            await d.put('chunks', encrypted, chunkKey(c, i));
            if (i % 10 === 0) progress(`Encrypting file: ${Math.round((i + 1) / attachment.chunks * 100)}%`);
          }
          await publishAttachment(file);
        });
      });
    }
    case 'attachment-delete': {
      const key = unlocked(), active = envelope!, id = String(payload.id);
      const remove = async (send?: VaultRequest) => {
        const file = await (await db()).get('attachments', id);
        if (!file || file.context.vaultId !== active.context.vaultId || file.context.epoch !== active.context.epoch) {
          throw Error('This file could not be found.');
        }
        if (file.manifest && send) {
          attachmentDetails(file, key);
          await deleteVaultFile(send, file, key);
        } else if (!active.account && !file.remote) {
          await eraseLocalFile(file);
        } else {
          throw Error('Connect to the vault and unlock with your master password to delete this file.');
        }
      };
      if (account && syncEnabled()) await withVaultSession(active, account, remove);
      else await remove();
      return;
    }
    case 'attachment-read': {
      const d = await db(), a = await d.get('attachments', String(payload.id));
      if (!a) throw Error('This file could not be found.');
      if (a.offline === false && a.remote === false) throw Error('This file was missing from the restored server and is unavailable on this device.');
      const key = unlocked(), id = a.context.objectId, keep = payload.keep === true;
      const parts: BlobPart[] = [];
      async function consume(send?: VaultRequest) {
        await readAttachment(a!, key, envelope!.context, async i => {
          if (send) {
            const chunk = await downloadChunk(send, a!, i);
            if (keep) await d.put('chunks', chunk, chunkKey(a!.context, i));
            return chunk;
          }
          const chunk = await d.get('chunks', chunkKey(a!.context, i));
          if (!chunk) throw Error('Missing encrypted chunk'); return chunk;
        }, async bytes => {
          if (payload.download) parts.push(bytes.slice().buffer);
        });
      }
      if (a.offline === false) {
        if (!account || !envelope) throw Error('Connect to Vault to open this file');
        await withVaultSession(envelope, account, async send => {
          if (!keep) return consume(send);
          // Another tab may have finished caching while this one waited for the lock.
          if ((await d.get('attachments', id))?.offline === true) return consume();
          await saveAttachmentChunks(d, a.context, a.chunks, async () => {
            await consume(send);
            await d.put('attachments', { ...a, offline: true }, id);
          });
        });
      } else await consume();
      return { name: attachmentDetails(a, key).displayName, verifiedBytes: a.size,
        blob: payload.download ? new Blob(parts, { type: 'application/octet-stream' }) : undefined };
    }
    default: throw Error('Unsupported worker request');
  }
}
// Serializing prevents overlapping calibration/unlock operations and mutable key races.
let queue = Promise.resolve();
function enqueue(action: () => void | Promise<void>) { queue = queue.then(action); return queue; }
type Request = { id: number; type: string; payload: Record<string, unknown> };
function receive(event: MessageEvent<Request>, send: (message: unknown) => void) {
  const { id, type, payload } = event.data;
  void enqueue(async () => {
    try { send({ id, result: await handle(type, payload, progress => send({ progress }), (done, total) => send({ id, steps: { done, total } })) }); }
    catch (e) { send({ id, error: e instanceof Error ? e.message : 'Operation failed' }); }
  });
}
if ('onconnect' in self) {
  (self as unknown as SharedWorkerGlobalScope).onconnect = event => {
    const port = event.ports[0];
    port.onmessage = request => receive(request, result => port.postMessage(result));
  };
} else {
  self.onmessage = event => receive(event, result => self.postMessage(result));
}
