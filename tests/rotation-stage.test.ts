import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { expect, it } from 'vitest';
import { stageRotation } from '../scripts/stage-vault-rotation';
import { chunkAad, readAttachment, startAttachment } from '../src/attachments';
import { createVault, decryptRecord, encryptRecord, identifierKey, ready, recoverDeviceKey, sodium, unlock } from '../src/crypto';
import { attachmentDetails, fileManifest, unpackAttachment } from '../src/file-sync';
import { CHUNK_BYTES, context, uuidBytes } from '../src/format';
import { parseRecoveryText } from '../src/recovery-key';
import { packConfig, packRevision, unpackConfig, unpackRevision } from '../src/wire';

it('builds a verified rotation stage with stable record IDs and streaming attachments', async () => {
  await ready();
  const work = await mkdtemp(join(tmpdir(), 'voltura-rotation-test-'));
  try {
    const source = join(work, 'source'), destination = join(work, 'candidate'), recoveryDestination = join(work, 'offline.vvrk');
    await mkdir(source);
    const oldPassword = 'Synthetic old å', newPassword = 'Synthetic replacement ä';
    const oldRecovery = sodium.randombytes_buf(32), deviceKey = sodium.randombytes_buf(32), account = sodium.randombytes_buf(32);
    const { root, envelope } = createVault(oldPassword, { algorithm: 'argon2id13', memory: 64 * 1024 ** 2,
      passes: 3, salt: sodium.randombytes_buf(16) }, account, { deviceKey, recoveryKey: oldRecovery });
    const { vaultId } = envelope.context;
    const rootKey = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', root);
    const record = encryptRecord('Syntetisk hemlighet  ', root, context(vaultId), []);
    const next = encryptRecord('Syntetisk ändring  ', root, context(vaultId, record.context.objectId), [record.context.revisionId]);
    const file = startAttachment(root, context(vaultId), CHUNK_BYTES + 4);
    const { objectId, revisionId } = file.attachment.context;
    const manifest = fileManifest(file.attachment, 'synthetic.pdf', root, record.context.objectId);
    const blobs = join(source, 'vault.blobs', objectId);
    await mkdir(blobs, { recursive: true });
    const originalChunks = [Buffer.alloc(CHUNK_BYTES, 9), Buffer.from([1, 2, 3, 4])];
    for (const [index, plain] of originalChunks.entries()) {
      const tag = index ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      await writeFile(join(blobs, String(index)), sodium.crypto_secretstream_xchacha20poly1305_push(
        file.state, plain, chunkAad(file.attachment.context, index), tag));
    }
    const db = new DatabaseSync(join(source, 'vault.sqlite3'));
    db.exec(`PRAGMA user_version=4;
      CREATE TABLE owner(singleton INTEGER PRIMARY KEY,vault TEXT,account BLOB,recovery BLOB,encrypted_config TEXT,key_epoch INTEGER);
      CREATE TABLE sessions(digest BLOB);
      CREATE TABLE sync_generation(singleton INTEGER,value TEXT);
      CREATE TABLE revisions(seq INTEGER PRIMARY KEY,vault TEXT,object TEXT,revision TEXT,mutation TEXT,envelope TEXT);
      CREATE TABLE files(vault TEXT,object TEXT,revision TEXT,size INTEGER,manifest TEXT,published INTEGER);
      CREATE TABLE revision_heads(vault TEXT,object TEXT,revision TEXT);`);
    const accountDigest = createHash('sha256').update('voltura-vault:token-verifier:v1\0').update(uuidBytes(vaultId))
      .update(Uint8Array.of(1)).update(account).digest();
    db.prepare('INSERT INTO owner VALUES(1,?,?,?,?,1)').run(vaultId, accountDigest, Buffer.alloc(32), packConfig(envelope));
    db.prepare('INSERT INTO sync_generation VALUES(1,?)').run('a'.repeat(32));
    for (const [index, r] of [record, next].entries()) db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?)')
      .run(index + 1, vaultId, r.context.objectId, r.context.revisionId, r.mutationId, JSON.stringify(packRevision(r, rootKey)));
    db.prepare('INSERT INTO files VALUES(?,?,?,?,?,1)').run(vaultId, objectId, revisionId, file.attachment.size, manifest);
    db.close();
    const input = { source, destination, recoveryDestination, oldRecovery, oldPassword, newPassword };
    await expect(stageRotation({ ...input, oldPassword: 'wrong' })).rejects.toThrow();
    await expect(readFile(recoveryDestination)).rejects.toMatchObject({ code: 'ENOENT' });
    const chunkPath = join(blobs, '1'), originalCiphertext = await readFile(chunkPath);
    const corrupted = Buffer.from(originalCiphertext);
    corrupted[0] ^= 1;
    await writeFile(chunkPath, corrupted);
    await expect(stageRotation(input)).rejects.toThrow();
    await expect(readFile(join(destination, 'rotation-point.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    const poison = new DatabaseSync(join(source, 'vault.sqlite3'));
    const forged = { ...packRevision(next, rootKey), revisionId: crypto.randomUUID(), mutationId: crypto.randomUUID() };
    poison.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?)').run(3, vaultId, forged.objectId, forged.revisionId,
      forged.mutationId, JSON.stringify(forged));
    poison.close();
    await expect(stageRotation(input)).rejects.toThrow();
    const quarantineStage = join(work, 'quarantine'), quarantineRecovery = join(work, 'quarantine.vvrk');
    await expect(stageRotation({ ...input, destination: quarantineStage, recoveryDestination: quarantineRecovery,
      quarantineInvalid: true })).resolves.toEqual({ revisions: 2, files: 0, epoch: 2, quarantined: 2 });
    const report = JSON.parse(await readFile(join(quarantineStage, 'quarantine.json'), 'utf8'));
    expect(report.map((entry: { id: string }) => entry.id)).toEqual([forged.revisionId, objectId]);
    expect(await readFile(chunkPath)).toEqual(corrupted);
    const linuxServer = process.env.VOLTURA_TEST_SERVER_LINUX_PATH;
    const onWindows = process.platform === 'win32';
    const linuxPath = (path: string) => onWindows
      ? execFileSync('wsl.exe', ['-d', 'Ubuntu', '--exec', 'wslpath', '-a', '-u', path.replaceAll('\\', '/')], { encoding: 'utf8' }).trim() : path;
    const activate = (data: string, candidate: string, floor: string, quarantine = false) => {
      const run = ['env', `VOLTURA_KEY_EPOCH_FLOOR=${linuxPath(floor)}`, linuxServer!, 'activate-rotation',
        ...[data, join(candidate, 'replacement.sqlite3'), join(candidate, 'rotation-point.json')].map(linuxPath)];
      if (quarantine) run.push('--quarantine-invalid');
      return onWindows ? execFileSync('wsl.exe', ['-d', 'Ubuntu', '--exec', ...run], { encoding: 'utf8' })
        : execFileSync(run[0], run.slice(1), { encoding: 'utf8' });
    };
    if (linuxServer) {
      const copy = join(work, 'quarantine-live');
      await cp(source, copy, { recursive: true });
      const floor = join(work, 'quarantine-epoch');
      await writeFile(floor, '1\n');
      expect(activate(copy, quarantineStage, floor, true)).toContain('Replacement vault activated');
      const rotated = new DatabaseSync(join(copy, 'vault.sqlite3'), { readOnly: true });
      try {
        expect(rotated.prepare('SELECT count(*) AS count FROM revisions').get()?.count).toBe(2);
        expect(rotated.prepare('SELECT count(*) AS count FROM files').get()?.count).toBe(0);
        expect(rotated.prepare('SELECT revision FROM revision_heads').get()?.revision).toBe(next.context.revisionId);
      } finally { rotated.close(); }
    }
    const clean = new DatabaseSync(join(source, 'vault.sqlite3'));
    clean.exec('DELETE FROM revisions WHERE seq=3');
    clean.close();
    await writeFile(chunkPath, originalCiphertext);

    await expect(stageRotation(input)).resolves.toEqual({ revisions: 2, files: 1, epoch: 2 });
    const point = JSON.parse(await readFile(join(destination, 'rotation-point.json'), 'utf8'));
    expect(point).toEqual({ vaultId, epoch: 1, generation: 'a'.repeat(32), lastRevision: 2, lastAttachment: 1,
      replacementInventory: expect.stringMatching(/^[A-Za-z0-9+/]{43}=$/) });
    const replacement = new DatabaseSync(join(destination, 'replacement.sqlite3'), { readOnly: true });
    try {
      const row = replacement.prepare('SELECT encrypted_config FROM owner').get()!;
      const rotated = unpackConfig(row.encrypted_config, vaultId, 2);
      const recovery = parseRecoveryText(await readFile(recoveryDestination, 'utf8'));
      const newDevice = recoverDeviceKey(rotated, recovery);
      expect(() => recoverDeviceKey(rotated, oldRecovery)).toThrow();
      expect(() => unlock(oldPassword, rotated, undefined, newDevice)).toThrow();
      const newRoot = unlock(newPassword, rotated, undefined, newDevice);
      expect(newRoot).not.toEqual(root);
      for (const label of ['VVSRCID1', 'VVFOLD01', 'VVBWID01'] as const) {
        const prior = identifierKey(envelope, root, label);
        const replacement = identifierKey(rotated, newRoot, label);
        if (label === 'VVFOLD01') expect(replacement).not.toEqual(prior);
        else expect(replacement).toEqual(prior);
      }
      const newSync = sodium.crypto_kdf_derive_from_key(32, 1, 'VVSYNC01', newRoot);
      const revisions = replacement.prepare('SELECT envelope FROM revisions ORDER BY seq').all();
      const restored = unpackRevision(JSON.parse(String(revisions[1].envelope)), rotated.context, newRoot, newSync);
      expect(restored.context.revisionId).toBe(next.context.revisionId);
      expect(restored.parents).toEqual(next.parents);
      expect(decryptRecord(restored, newRoot, rotated.context)).toBe('Syntetisk ändring  ');
      const rotatedFile = unpackAttachment({ objectId, revisionId, size: file.attachment.size, epoch: 2,
        manifest: String(replacement.prepare('SELECT manifest FROM files').get()!.manifest) }, rotated.context, newRoot);
      expect(attachmentDetails(rotatedFile, newRoot)).toEqual({ displayName: 'synthetic.pdf', recordId: record.context.objectId });
      const opened: Uint8Array[] = [];
      await readAttachment(rotatedFile, newRoot, rotated.context,
        part => readFile(join(destination, 'vault.blobs', 'epoch-2', objectId, String(part))),
        async plain => { opened.push(plain.slice()); });
      expect(opened.map(bytes => Buffer.from(bytes))).toEqual(originalChunks);
    } finally { replacement.close(); }

    if (linuxServer) {
      await cp(join(destination, 'vault.blobs', 'epoch-2'), join(source, 'vault.blobs', 'epoch-2'), { recursive: true });
      const floor = join(work, 'trusted-epoch');
      await writeFile(floor, '1\n');
      const output = activate(source, destination, floor);
      expect(output).toContain('Replacement vault activated');
      expect(await readFile(floor, 'utf8')).toBe('2\n');
      const activated = new DatabaseSync(join(source, 'vault.sqlite3'), { readOnly: true });
      try {
        const active = activated.prepare('SELECT key_epoch, encrypted_config FROM owner').get()!;
        const envelope = unpackConfig(active.encrypted_config, vaultId, Number(active.key_epoch));
        const recovery = parseRecoveryText(await readFile(recoveryDestination, 'utf8'));
        expect(active.key_epoch).toBe(2);
        expect(unlock(newPassword, envelope, undefined, recoverDeviceKey(envelope, recovery))).toHaveLength(32);
      } finally { activated.close(); }
    }
  } finally {
    // The test owns this uniquely created directory below the OS temp root.
    await rm(work, { recursive: true, force: true });
  }
}, 15_000);
