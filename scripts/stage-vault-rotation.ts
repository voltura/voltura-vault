import { createHash } from 'node:crypto';
import { lstat, mkdir, open as openFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, isAbsolute } from 'node:path';
import { emitKeypressEvents } from 'node:readline';
import { DatabaseSync } from 'node:sqlite';
import { AttachmentAuthenticationError, readAttachment, rewriteAttachment } from '../src/attachments.ts';
import { createRotatedVault, identifierKey, ready, recoverDeviceKey, rewriteRevision, sodium, unlock, validateNewMasterPassword, wipe } from '../src/crypto.ts';
import { attachmentDetails, fileManifest, unpackAttachment } from '../src/file-sync.ts';
import { uuidBytes, type Revision } from '../src/format.ts';
import { parseRecoveryText, recoveryText } from '../src/recovery-key.ts';
import { packConfig, packRevision, unpackConfig, unpackRevision } from '../src/wire.ts';

type Owner = { vault: string; account: Uint8Array; recovery: Uint8Array; encrypted_config: string; epoch: number };
type RecordRow = { seq: number; vault: string; object: string; revision: string; mutation: string; envelope: string };
type FileRow = { vault: string; object: string; revision: string; size: number; manifest: string; published: number };
type Input = {
  source: string; destination: string; recoveryDestination: string;
  oldPassword: string; newPassword: string; oldRecovery: Uint8Array; quarantineInvalid?: boolean;
};

const verifier = (secret: Uint8Array, vault: string, purpose: number) => createHash('sha256')
  .update('voltura-vault:token-verifier:v1\0').update(uuidBytes(vault))
  .update(Uint8Array.of(purpose)).update(secret).digest();

async function assertType(path: string, directory: boolean) {
  const entry = await lstat(path);
  if (directory ? !entry.isDirectory() : !entry.isFile()) throw Error('Rotation requires regular snapshot files and directories');
  return entry;
}

async function readBounded(path: string, maximum: number) {
  if ((await assertType(path, false)).size > maximum) throw Error('Snapshot file exceeds its size limit');
  const file = await openFile(path, 'r');
  try {
    const { size } = await file.stat();
    if (size > maximum) throw Error('Snapshot file exceeds its size limit');
    const bytes = Buffer.alloc(size);
    if ((await file.read(bytes, 0, size, 0)).bytesRead !== size) throw Error('Snapshot file changed during read');
    return bytes;
  } finally { await file.close(); }
}

function blobRoot(base: string, epoch: number) {
  return epoch === 1 ? join(base, 'vault.blobs') : join(base, 'vault.blobs', `epoch-${epoch}`);
}

async function rewriteFile(row: FileRow, source: string, destination: string, owner: Owner, oldRoot: Uint8Array, newRoot: Uint8Array) {
  let old;
  try {
    old = unpackAttachment({ objectId: row.object, revisionId: row.revision,
      epoch: owner.epoch, size: row.size, manifest: row.manifest }, { vaultId: owner.vault, epoch: owner.epoch }, oldRoot);
  } catch { throw new AttachmentAuthenticationError('Attachment manifest failed authentication'); }
  const { displayName, recordId } = attachmentDetails(old, oldRoot);
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(row.object)) throw Error('Invalid snapshot attachment identifier');
  const context = { ...old.context, epoch: owner.epoch + 1 };
  const oldRootDir = blobRoot(source, owner.epoch);
  const oldDirectory = join(oldRootDir, row.object);
  const newDirectory = join(blobRoot(destination, context.epoch), row.object);
  await assertType(join(source, 'vault.blobs'), true);
  await assertType(oldRootDir, true);
  await assertType(oldDirectory, true);
  await mkdir(newDirectory, { recursive: true, mode: 0o700 });
  const oldHash = createHash('sha256'), newHash = createHash('sha256');
  let attachment;
  try {
    attachment = await rewriteAttachment(old, oldRoot, newRoot, context.epoch,
      part => readBounded(join(oldDirectory, String(part)), 1_048_593), async (index, encrypted, plain) => {
      oldHash.update(plain);
      await writeFile(join(newDirectory, String(index)), encrypted, { flag: 'wx', mode: 0o600 });
    });
  } catch (error) {
    if (error instanceof AttachmentAuthenticationError) await rm(newDirectory, { recursive: true, force: true });
    throw error;
  }
  const manifest = fileManifest(attachment, displayName, newRoot, recordId);
  const staged = unpackAttachment({ objectId: row.object, revisionId: row.revision, epoch: context.epoch,
    size: row.size, manifest }, context, newRoot);
  const details = attachmentDetails(staged, newRoot);
  const chunkDigests: string[] = [];
  await readAttachment(staged, newRoot, context, async part => {
    const bytes = await readBounded(join(newDirectory, String(part)), 1_048_593);
    chunkDigests.push(createHash('sha256').update(bytes).digest('base64'));
    return bytes;
  },
    async plain => { newHash.update(plain); });
  if (!oldHash.digest().equals(newHash.digest()) || details.displayName !== displayName || details.recordId !== recordId) {
    throw Error('Replacement attachment differs from the authenticated original');
  }
  return { manifest, chunkDigests };
}

function isWithin(parent: string, child: string) {
  const path = relative(parent, child);
  return path === '' || (!isAbsolute(path) && path !== '..' && !/^\.\.[\\/]/.test(path));
}

export async function stageRotation(input: Input) {
  const source = resolve(input.source), destination = resolve(input.destination), recoveryDestination = resolve(input.recoveryDestination);
  if (isWithin(source, destination) || isWithin(source, recoveryDestination) || isWithin(destination, recoveryDestination)) {
    throw Error('Keep the snapshot, replacement directory and new offline recovery file separate');
  }
  validateNewMasterPassword(input.newPassword);
  if (input.oldPassword.normalize('NFC') === input.newPassword.normalize('NFC')) throw Error('Choose a different master password');
  await ready();
  await assertType(source, true);
  const sourceDb = join(source, 'vault.sqlite3');
  await assertType(sourceDb, false);
  const snapshot = new DatabaseSync(sourceDb, { readOnly: true });
  let oldRoot: Uint8Array | undefined, newRoot: Uint8Array | undefined;
  let newAccount: Uint8Array | undefined, newDevice: Uint8Array | undefined, newRecovery: Uint8Array | undefined;
  let oldSync: Uint8Array | undefined, newSync: Uint8Array | undefined;
  let stageCreated = false, completed = false;
  try {
    snapshot.exec('PRAGMA trusted_schema=OFF; BEGIN;');
    const version = snapshot.prepare('PRAGMA user_version').get()?.user_version;
    if (typeof version !== 'number' || ![3, 4, 5, 6, 7, 8].includes(version)) throw Error('Unsupported rotation snapshot schema');
    const owner = snapshot.prepare(`SELECT vault,account,recovery,encrypted_config,${version >= 4 ? 'key_epoch' : '1'} AS epoch FROM owner WHERE singleton=1`).get() as Owner | undefined;
    if (!owner) throw Error('Rotation snapshot has no owner');
    const old = unpackConfig(owner.encrypted_config, owner.vault, owner.epoch);
    const oldDevice = recoverDeviceKey(old, input.oldRecovery);
    try {
      oldRoot = unlock(input.oldPassword, old, account => {
        if (!sodium.memcmp(verifier(account, owner.vault, 1), owner.account)) throw Error('Snapshot account did not authenticate');
      }, oldDevice);
    } finally { wipe(oldDevice); }

    const inventory = createHash('sha256');
    const replacementInventory = createHash('sha256');
    const bind = (fields: (string | number)[]) => bindInventory(inventory, fields);
    const bindReplacement = (fields: (string | number)[]) => bindInventory(replacementInventory, fields);
    bind([owner.encrypted_config, Buffer.from(owner.account).toString('hex').toUpperCase(),
      Buffer.from(owner.recovery).toString('hex').toUpperCase()]);
    const point = snapshot.prepare(`SELECT ? AS vaultId, ? AS epoch,
      (SELECT value FROM sync_generation WHERE singleton=1) AS generation,
      (SELECT coalesce(max(seq),0) FROM revisions) AS lastRevision,
      (SELECT coalesce(max(published),0) FROM files) AS lastAttachment`).get(owner.vault, owner.epoch);
    if (typeof point?.generation !== 'string' || !/^[a-f0-9]{32}$/.test(point.generation)) throw Error('Invalid snapshot generation');
    newAccount = sodium.randombytes_buf(32);
    newDevice = sodium.randombytes_buf(32);
    newRecovery = sodium.randombytes_buf(32);
    const result = createRotatedVault(old, oldRoot, input.newPassword, newAccount, newDevice, newRecovery);
    newRoot = result.root;
    const config = packConfig(result.envelope);
    const replacement = unpackConfig(config, owner.vault, owner.epoch + 1);
    const accountVerifier = verifier(newAccount, owner.vault, 1);
    const recoveryVerifier = verifier(newRecovery, owner.vault, 2);
    bindReplacement(['voltura-vault:rotation-replacement:v1', config,
      accountVerifier.toString('hex').toUpperCase(), recoveryVerifier.toString('hex').toUpperCase()]);
    const checkRecovery = parseRecoveryText(recoveryText(newRecovery));
    let checkDevice: Uint8Array | undefined, checkRoot: Uint8Array | undefined;
    try {
      checkDevice = recoverDeviceKey(replacement, checkRecovery);
      checkRoot = unlock(input.newPassword, replacement, account => {
        if (!sodium.memcmp(verifier(account, owner.vault, 1), accountVerifier)) throw Error('Replacement account did not authenticate');
      }, checkDevice);
      if (!sodium.memcmp(newRoot, checkRoot)) throw Error('Replacement recovery did not recover the vault key');
      for (const label of ['VVSRCID1', 'VVFOLD01', 'VVBWID01'] as const) {
        const previous = identifierKey(old, oldRoot, label);
        let next: Uint8Array | undefined;
        try {
          next = identifierKey(replacement, checkRoot, label);
          if (sodium.memcmp(previous, next) === (label === 'VVFOLD01')) throw Error('Replacement identifier key is invalid');
        } finally { wipe(previous); wipe(next); }
      }
    } finally { wipe(checkRecovery); wipe(checkDevice); wipe(checkRoot); }

    await mkdir(destination, { mode: 0o700 });
    stageCreated = true;
    const replacementPath = join(destination, 'replacement.sqlite3');
    // Create exclusively with private permissions before SQLite opens the file.
    await writeFile(replacementPath, '', { flag: 'wx', mode: 0o600 });
    const stage = new DatabaseSync(replacementPath);
    let revisions = 0, files = 0;
    const quarantined: { kind: 'revision' | 'attachment'; id: string; reason: string }[] = [];
    try {
      stage.exec(`BEGIN;
        CREATE TABLE owner(singleton INTEGER PRIMARY KEY,vault TEXT,account BLOB,recovery BLOB,encrypted_config TEXT,key_epoch INTEGER);
        CREATE TABLE revisions(seq INTEGER PRIMARY KEY,vault TEXT,object TEXT,revision TEXT UNIQUE,mutation TEXT UNIQUE,envelope TEXT);
        CREATE TABLE files(vault TEXT,object TEXT PRIMARY KEY,revision TEXT,size INTEGER,manifest TEXT,published INTEGER UNIQUE);`);
      if (input.quarantineInvalid) stage.exec(`
        CREATE TABLE quarantined_revisions AS SELECT * FROM revisions WHERE 0;
        CREATE TABLE quarantined_files AS SELECT * FROM files WHERE 0;`);
      stage.prepare('INSERT INTO owner VALUES(1,?,?,?,?,?)').run(owner.vault, accountVerifier, recoveryVerifier, config, replacement.context.epoch);
      oldSync = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', oldRoot);
      newSync = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', newRoot);
      const insertRevision = stage.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?)');
      for (const row of snapshot.prepare('SELECT seq,vault,object,revision,mutation,envelope FROM revisions ORDER BY seq').iterate() as Iterable<RecordRow>) {
        if (!Number.isSafeInteger(row.seq)) throw Error('Invalid snapshot revision sequence');
        bind(['revision', row.seq, row.vault, row.object, row.revision, row.mutation, row.envelope]);
        let wire: Revision;
        try { wire = unpackRevision(JSON.parse(row.envelope), old.context, oldRoot, oldSync); }
        catch (error) {
          if (!input.quarantineInvalid) throw error;
          stage.prepare('INSERT INTO quarantined_revisions VALUES(?,?,?,?,?,?)')
            .run(row.seq, row.vault, row.object, row.revision, row.mutation, row.envelope);
          quarantined.push({ kind: 'revision', id: row.revision, reason: 'Failed authentication' });
          continue;
        }
        if (row.vault !== owner.vault || row.object !== wire.context.objectId || row.revision !== wire.context.revisionId || row.mutation !== wire.mutationId) {
          throw Error('Snapshot revision identity does not match its authenticated record');
        }
        const rewritten = rewriteRevision(wire, oldRoot, old.context, newRoot, replacement.context.epoch);
        const encoded = packRevision(rewritten, newSync);
        unpackRevision(encoded, replacement.context, newRoot, newSync);
        const rewrittenEnvelope = JSON.stringify(encoded);
        insertRevision.run(row.seq, row.vault, row.object, row.revision, row.mutation, rewrittenEnvelope);
        bindReplacement(['revision', row.seq, row.vault, row.object, row.revision, row.mutation, rewrittenEnvelope]);
        revisions++;
      }
      const insertFile = stage.prepare('INSERT INTO files VALUES(?,?,?,?,?,?)');
      for (const row of snapshot.prepare('SELECT vault,object,revision,size,manifest,published FROM files WHERE published IS NOT NULL ORDER BY published').iterate() as Iterable<FileRow>) {
        if (row.vault !== owner.vault) throw Error('Snapshot attachment belongs to another vault');
        if (!Number.isSafeInteger(row.published) || !Number.isSafeInteger(row.size) || row.size < 0 || row.size > 100_000_000) {
          throw Error('Invalid published attachment inventory');
        }
        bind(['file', row.published, row.vault, row.object, row.revision, row.size, row.manifest]);
        if (input.quarantineInvalid) {
          if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(row.object)) throw Error('Invalid snapshot attachment identifier');
          const directory = join(blobRoot(source, owner.epoch), row.object);
          for (let part = 0; part < Math.max(1, Math.ceil(row.size / 1_048_576)); part++) {
            const bytes = await readBounded(join(directory, String(part)), 1_048_593);
            bind([createHash('sha256').update(bytes).digest('base64')]);
          }
        }
        let replacementFile: Awaited<ReturnType<typeof rewriteFile>>;
        try { replacementFile = await rewriteFile(row, source, destination, owner, oldRoot, newRoot); }
        catch (error) {
          if (!input.quarantineInvalid || !(error instanceof AttachmentAuthenticationError)) throw error;
          stage.prepare('INSERT INTO quarantined_files VALUES(?,?,?,?,?,?)')
            .run(row.vault, row.object, row.revision, row.size, row.manifest, row.published);
          quarantined.push({ kind: 'attachment', id: row.object, reason: error.message });
          continue;
        }
        const { manifest, chunkDigests } = replacementFile;
        insertFile.run(row.vault, row.object, row.revision, row.size, manifest, row.published);
        bindReplacement(['file', row.published, row.vault, row.object, row.revision, row.size, manifest, ...chunkDigests]);
        files++;
      }
      if (input.quarantineInvalid && stage.prepare(`SELECT 1 FROM revisions AS child, json_each(child.envelope, '$.parents') AS edge
        WHERE NOT EXISTS (SELECT 1 FROM revisions AS parent WHERE parent.revision=edge.value
          AND parent.vault=child.vault AND parent.object=child.object AND parent.seq<child.seq) LIMIT 1`).get()) {
        throw Error('An authenticated revision depends on an unavailable parent');
      }
      stage.exec('COMMIT;');
    } finally { stage.close(); }
    if (input.quarantineInvalid) await writeFile(join(destination, 'quarantine.json'), JSON.stringify(quarantined), { flag: 'wx', mode: 0o600 });
    await writeFile(recoveryDestination, recoveryText(newRecovery), { flag: 'wx', mode: 0o600, flush: true });
    await writeFile(join(destination, 'rotation-point.json'), JSON.stringify({ ...point,
      ...(input.quarantineInvalid && { inventory: inventory.digest('base64') }),
      replacementInventory: replacementInventory.digest('base64') }), { flag: 'wx', mode: 0o600, flush: true });
    completed = true;
    return { revisions, files, epoch: replacement.context.epoch, ...(input.quarantineInvalid && { quarantined: quarantined.length }) };
  } finally {
    snapshot.close();
    for (const secret of [oldRoot, newRoot, newAccount, newDevice, newRecovery, oldSync, newSync]) wipe(secret);
    if (stageCreated && !completed && dirname(destination) !== destination) {
      await rm(destination, { recursive: true, force: true });
    }
  }
}

function bindInventory(digest: ReturnType<typeof createHash>, fields: (string | number)[]) {
  for (const field of fields) {
    const bytes = Buffer.from(String(field));
    digest.update(String(bytes.length)).update(':').update(bytes);
  }
}

async function readPassword(prompt: string): Promise<string> {
  const { stdin, stdout } = process;
  if (!stdin.isTTY || !stdout.isTTY) throw Error('Use a local terminal for hidden password entry');
  emitKeypressEvents(stdin);
  stdout.write(prompt);
  stdin.setRawMode(true);
  stdin.resume();
  try {
    return await new Promise<string>((resolvePassword, reject) => {
      const input: string[] = [];
      const keypress = (text: string | undefined, key: { name?: string; ctrl?: boolean; meta?: boolean }) => {
        if (key.ctrl && key.name === 'c') { stdin.off('keypress', keypress); reject(Error('Rotation cancelled')); }
        else if (key.name === 'return' || key.name === 'enter') { stdin.off('keypress', keypress); resolvePassword(input.join('')); }
        else if (key.name === 'backspace') input.pop();
        else if (text && !key.ctrl && !key.meta && !/[\x00-\x1f\x7f]/.test(text)) input.push(text);
      };
      stdin.on('keypress', keypress);
    });
  } finally { stdin.setRawMode(false); stdin.pause(); stdout.write('\n'); }
}

async function main() {
  const [source, destination, oldRecoveryPath, recoveryDestination, mode] = process.argv.slice(2);
  if (process.argv.length < 6 || process.argv.length > 7 || (mode !== undefined && mode !== '--quarantine-invalid')) {
    throw Error('Usage: stage-vault-rotation SNAPSHOT NEW_STAGE OLD_RECOVERY_FILE NEW_OFFLINE_RECOVERY_FILE [--quarantine-invalid]');
  }
  await ready();
  const recoveryBytes = await readBounded(oldRecoveryPath, 128);
  let oldRecovery: Uint8Array | undefined;
  try {
    oldRecovery = parseRecoveryText(recoveryBytes.toString('utf8'));
    const oldPassword = await readPassword('Current vault master password: ');
    const newPassword = await readPassword('New vault master password: ');
    if (newPassword !== await readPassword('Repeat new vault master password: ')) throw Error('The new passwords do not match');
    const result = await stageRotation({ source, destination, recoveryDestination, oldRecovery, oldPassword, newPassword,
      quarantineInvalid: mode === '--quarantine-invalid' });
    console.log(`Verified ${result.revisions} revisions and ${result.files} attachments for key epoch ${result.epoch}.`);
    if (result.quarantined) console.log(`Review ${result.quarantined} entries in quarantine.json and retain the original encrypted snapshot before activation.`);
  } finally { wipe(recoveryBytes); wipe(oldRecovery); }
}

if (import.meta.main) {
  main().catch(() => {
    console.error('Rotation staging did not complete. Check the snapshot, recovery file, passwords and destination paths.');
    process.exitCode = 1;
  });
}
