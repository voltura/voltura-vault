import { describe, expect, it } from 'vitest';
import { changeFieldType, fieldType } from '../src/fields';
import { itemDraft, makeItem, reviseItem } from '../src/item-editor';
import type { ImportedItem } from '../src/bitwarden';

describe('editing Bitwarden-compatible item fields', () => {
  it('keeps malformed linked fields opaque without coercing their IDs', () => {
    const malformed = { name: 'Imported', type: 3, linkedId: { toString: 0 } };
    const item: ImportedItem = { name: 'Sample', kind: 'Login', folder: '', source: { type: 1, fields: [malformed] } };
    const draft = itemDraft(item);
    expect(fieldType(draft.fields[0])).toBe('preserved');
    expect(reviseItem(item, draft, '')?.source.fields).toEqual([malformed]);
  });
  it('renames, edits and reorders URLs without losing imported fields or metadata', () => {
    const item: ImportedItem = { name: 'Original', kind: 'Login', folder: 'Old', source: {
      type: 1, id: 'synthetic', login: { username: 'sample', password: 'old', totp: 'synthetic-seed',
        uris: [{ uri: 'https://first.example', match: 3, futureValue: 7 }, { uri: 'https://second.example', match: 1 }],
        fido2Credentials: [{ synthetic: true }] },
      fields: [{ name: 'Original field', value: '  keep whitespace  ', type: 1 }, { name: 'Linked username', type: 3, linkedId: 100, value: null }],
      passwordHistory: [{ password: 'older', lastUsedDate: '2026-01-01T00:00:00Z' }],
    } };
    const draft = itemDraft(item);
    draft.name = 'Renamed'; draft.folder = 'New folder'; draft.favorite = true;
    draft.values.password = 'new';
    draft.urls.reverse(); draft.urls.push({ uri: 'https://third.example', match: null });
    draft.fields[0] = { ...draft.fields[0], name: 'Renamed hidden field' };
    draft.fields.push(changeFieldType({ name: 'Count', type: 0, value: '123.50' }, 'number'));
    const edited = reviseItem(item, draft, '')!;
    expect(edited.name).toBe('Renamed');
    expect(edited.source.id).toBe('synthetic');
    expect(edited.source.login).toMatchObject({
      username: 'sample', password: 'new', totp: 'synthetic-seed', fido2Credentials: [{ synthetic: true }],
      uris: [{ uri: 'https://second.example', match: 1 }, { uri: 'https://first.example', match: 3, futureValue: 7 }, { uri: 'https://third.example', match: null }],
    });
    expect(itemDraft(edited).fields.map(field => [field.name, fieldType(field), field.value])).toEqual([
      ['Renamed hidden field', 'hidden', '  keep whitespace  '], ['Linked username', 'linked', null], ['Count', 'number', '123.50'],
    ]);
    expect(edited.source.passwordHistory).toMatchObject([{ password: 'old' }, { password: 'older' }]);
  });

  it('supports card and identity links and validates numeric values', () => {
    for (const [type, linkedId] of [[3, 305], [4, 418]] as const) {
      const item = makeItem(type), draft = itemDraft(item);
      draft.fields.push(changeFieldType({ name: 'Linked value', type: 0 }, 'linked', linkedId));
      expect(itemDraft(reviseItem(item, draft, '')).fields[0].linkedId).toBe(linkedId);
      draft.fields.push(changeFieldType({ name: 'Count', type: 0, value: 'no' }, 'number'));
      expect(() => reviseItem(item, draft, '')).toThrow('Enter a number for Count');
    }
  });

  it('leaves old plain notes readable and preserves opaque imported fields', () => {
    expect(reviseItem(undefined, itemDraft(undefined, 'old note'), 'edited note')).toBeUndefined();
    const item = makeItem(2);
    const field = { name: null, type: 99, value: 'opaque source metadata' };
    item.source.fields = [field];
    const draft = itemDraft(item);
    draft.name = 'Renamed note';
    expect(reviseItem(item, draft, 'text')?.source.fields).toEqual([field]);
  });
});
