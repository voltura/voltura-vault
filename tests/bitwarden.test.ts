import { argon2Sync, createCipheriv, createHash, createHmac, pbkdf2Sync } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { decodeImported, encodeImported, parseBitwarden } from '../src/bitwarden';
import { ready } from '../src/crypto';
import { itemDraft, reviseItem } from '../src/item-editor';

const password = 'Synthetic export åäö';
const salt = 'Zml4ZWQtc3ludGhldGljLXNhbHQ=';
const json = {
  encrypted: false,
  folders: [{ id: 'folder-1', name: 'Test folder' }],
  items: [
    { id: 'test-login', type: 1, name: 'Synthetic login', folderId: 'folder-1', favorite: true,
      login: { username: 'test-user', password: '  sample åäö  ', totp: 'synthetic seed', uris: [{ uri: 'https://example.invalid' }] },
      fields: [{ name: 'test field', value: 'test value', type: 1 }], passwordHistory: [{ password: 'old synthetic' }],
      attachments: [{ id: 'fake', fileName: 'missing.bin' }] },
    { id: 'test-key', type: 5, name: 'Synthetic SSH', sshKey: { privateKey: 'synthetic key' } },
  ],
};
const blob = (value: unknown) => new Blob([JSON.stringify(value)]);

function encrypted(kdfType: 0 | 1) {
  const kdfIterations = kdfType === 0 ? 5000 : 2, kdfMemory = 16, kdfParallelism = 2;
  const key = kdfType === 0 ? pbkdf2Sync(password, salt, kdfIterations, 32, 'sha256')
    : argon2Sync('argon2id', { message: Buffer.from(password), nonce: createHash('sha256').update(salt).digest(),
      memory: kdfMemory * 1024, passes: kdfIterations, parallelism: kdfParallelism, tagLength: 32 });
  const enc = createHmac('sha256', key).update('enc\x01').digest();
  const mac = createHmac('sha256', key).update('mac\x01').digest();
  const seal = (text: string, fill: number) => {
    const iv = Buffer.alloc(16, fill), cipher = createCipheriv('aes-256-cbc', enc, iv);
    const data = Buffer.concat([cipher.update(text), cipher.final()]);
    const tag = createHmac('sha256', mac).update(iv).update(data).digest();
    return '2.' + [iv, data, tag].map(bytes => bytes.toString('base64')).join('|');
  };
  return { encrypted: true, passwordProtected: true, salt, kdfType, kdfIterations, kdfMemory, kdfParallelism,
    encKeyValidation_DO_NOT_EDIT: seal('synthetic validator', 1), data: seal(JSON.stringify(json), 2) };
}

beforeAll(ready);
describe('Bitwarden JSON import', () => {
  it('preserves fields, history, exact whitespace, folders and attachment references', async () => {
    const result = await parseBitwarden(blob(json), '');
    expect(result.summary).toEqual({ items: 2, folders: 1, attachments: 1, types: { Login: 1, 'SSH key': 1 },
      passkeys: 0, archived: 0, reprompt: 0, unresolvedFolders: 0 });
    expect(result.items[0].folder).toBe('Test folder');
    expect(decodeImported(encodeImported(result.items[0]))?.source).toEqual(json.items[0]);
    expect(result.items[1].source).toEqual(json.items[1]);
  });
  it.each([0, 1] as const)('opens password-protected export with KDF %d', async kdf => {
    const result = await parseBitwarden(blob(encrypted(kdf)), password);
    expect(result.items.map(item => item.source)).toEqual(json.items);
  });
  it('rejects wrong passwords, corrupt MACs, excessive KDF requests and account-restricted exports', async () => {
    const valid = encrypted(0);
    await expect(parseBitwarden(blob(valid), 'wrong')).rejects.toThrow('Wrong export password');
    const parts = valid.data.split('|');
    parts[2] = Buffer.alloc(32, 77).toString('base64');
    await expect(parseBitwarden(blob({ ...valid, data: parts.join('|') }), password)).rejects.toThrow('damaged export');
    await expect(parseBitwarden(blob({ ...valid, kdfIterations: 20_000_000 }), password)).rejects.toThrow('key derivation');
    await expect(parseBitwarden(blob({ ...valid, passwordProtected: false }), password)).rejects.toThrow('account-restricted');
  });
  it('opens current personal record types with editable fields and reports preserved migration metadata', async () => {
    const items = [
      { id: 'bank', type: 6, name: 'Synthetic bank', bankAccount: { accountNumber: '000123', pin: '0123' } },
      { id: 'licence', type: 7, name: 'Synthetic license', driversLicense: { licenseNumber: 'FAKE', expirationDate: '2030-01-01' } },
      { id: 'passport', type: 8, name: 'Synthetic passport', passport: { passportNumber: 'FAKE', givenName: 'Sample' } },
      { id: 'login', type: 1, name: 'Synthetic passkey', folderId: 'missing', reprompt: 1,
        archivedDate: '2025-01-01T00:00:00Z', login: { fido2Credentials: [{ keyValue: 'fixture' }] } },
    ];
    const result = await parseBitwarden(blob({ encrypted: false, items }), '');
    expect(result.summary).toMatchObject({ passkeys: 1, archived: 1, reprompt: 1, unresolvedFolders: 1 });
    expect(result.items.map(item => item.kind)).toEqual(['Bank account', 'Driver’s license', 'Passport', 'Login']);
    const [bank, license, passport] = result.items;
    expect(itemDraft(bank).values).toMatchObject({ accountNumber: '000123', pin: '0123' });
    expect(itemDraft(license).values.licenseNumber).toBe('FAKE');
    const draft = itemDraft(passport);
    draft.values.givenName = 'Edited';
    expect(reviseItem(passport, draft, '')?.source.passport).toEqual({ passportNumber: 'FAKE', givenName: 'Edited' });
  });
  it('rejects shared collections and opaque record blobs before any import can be committed', async () => {
    await expect(parseBitwarden(blob({ ...json, collections: [{ id: 'shared' }] }), '')).rejects.toThrow('organization collections');
    await expect(parseBitwarden(blob({ ...json, items: [{ type: 1, data: 'encrypted' }] }), '')).rejects.toThrow('unsupported Bitwarden data blob');
  });
  it('bounds the expanded import when many items reference the same large folder', async () => {
    const folder = { id: 'shared', name: 'a'.repeat(256) };
    const largeNote = 'a'.repeat(110_000);
    const items = Array.from({ length: 304 }, () => ({ type: 1, name: 'Synthetic', folderId: folder.id, notes: largeNote }));
    await expect(parseBitwarden(blob({ encrypted: false, folders: [folder], items }), '')).rejects.toThrow('exceed 32 MiB after expanding folders');
  });
  it('rejects an oversized folder before building even an empty folder record', async () => {
    const folders = [{ id: 'empty', name: 'a'.repeat(257) }];
    await expect(parseBitwarden(blob({ encrypted: false, folders, items: [] }), '')).rejects.toThrow('folder name exceeds 256 characters');
  });
  it('reports unknown nonzero re-prompt metadata as protected', async () => {
    const items = [{ type: 1, name: 'Synthetic', reprompt: '1' }];
    await expect(parseBitwarden(blob({ encrypted: false, items }), '')).resolves.toMatchObject({ summary: { reprompt: 1 } });
  });
});
