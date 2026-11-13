import type { ImportedItem } from './bitwarden';
import type { Revision } from './format';
import { itemDraft, itemType } from './item-editor';

export type Folder = { key: string; name: string; deleted?: true };
export type VaultRecord = {
  text: string;
  revision: Revision;
  item?: ImportedItem;
  folderEntry?: Folder;
  trashed?: boolean;
};

const FOLDER_PREFIX = '\x1evoltura-folder-v1\n';
export const TRASH_MARKER = '\x1evoltura-trash-v1';

export const encodeFolder = (folder: Folder) => FOLDER_PREFIX + JSON.stringify(folder);
export function decodeFolder(text: string): Folder | undefined {
  if (!text.startsWith(FOLDER_PREFIX)) return;
  try {
    const { key, name, deleted } = JSON.parse(text.slice(FOLDER_PREFIX.length));
    if (typeof key === 'string' && key && typeof name === 'string' && name) {
      return deleted === true ? { key, name, deleted: true } : { key, name };
    }
  } catch { /* An older note may start with the same characters. */ }
}

export function vaultFolders(records: VaultRecord[]): Folder[] {
  const folders = new Map<string, Folder>();
  const definitions = records.filter(record => record.folderEntry)
    .sort((a, b) => a.revision.context.revisionId.localeCompare(b.revision.context.revisionId));
  for (const { folderEntry } of definitions) {
    if (folderEntry && !folders.get(folderEntry.key)?.deleted) folders.set(folderEntry.key, folderEntry);
  }
  for (const { item } of records) {
    if (item?.folder && !folders.has(item.folder)) folders.set(item.folder, { key: item.folder, name: item.folder });
  }
  return [...folders.values()].filter(folder => !folder.deleted)
    .sort((a, b) => a.name.localeCompare(b.name) || a.key.localeCompare(b.key));
}

export const recordTitle = ({ item, text }: VaultRecord) => item?.name || text.trim().split('\n', 1)[0]?.slice(0, 80) || 'Untitled note';

export function matchesSearch(record: VaultRecord, query: string, folderName: string) {
  const draft = itemDraft(record.item);
  const searchable = [recordTitle(record), record.item?.kind ?? 'Secure note', folderName,
    draft.values.username, draft.values.email, ...draft.urls.map(url => url.uri)]
    .filter(Boolean).join('\n').toLocaleLowerCase();
  return query.trim().toLocaleLowerCase().split(/\s+/).every(word => searchable.includes(word));
}

export function quickCopies(record: VaultRecord): [string, string][] {
  const draft = itemDraft(record.item);
  const type = itemType(record.item);
  const options: [string, string | undefined][] =
    type === 1 ? [['username', draft.values.username], ['password', draft.values.password], ['website URL', draft.urls[0]?.uri]]
    : type === 3 ? [['card number', draft.values.number], ['security code', draft.values.code]]
    : type === 4 ? [['email', draft.values.email], ['username', draft.values.username], ['phone', draft.values.phone]]
    : type === 5 ? [['public key', draft.values.publicKey], ['private key', draft.values.privateKey], ['fingerprint', draft.values.keyFingerprint]]
    : [['note', record.text]];
  return options.filter((option): option is [string, string] => !!option[1]);
}
