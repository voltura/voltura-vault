import type { ImportedItem } from './bitwarden';
import { fieldsFrom, validateFieldEdits, type CustomField } from './fields';

export const ITEM_TYPES = { 1: 'Login', 2: 'Secure note', 3: 'Card', 4: 'Identity', 5: 'SSH key',
  6: 'Bank account', 7: 'Driver’s license', 8: 'Passport' } as const;
export type ItemType = keyof typeof ITEM_TYPES;
const sections: Partial<Record<number, { name: string; keys: string[] }>> = {
  1: { name: 'login', keys: ['username', 'password', 'totp'] },
  3: { name: 'card', keys: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'] },
  4: { name: 'identity', keys: ['title', 'firstName', 'middleName', 'lastName', 'username', 'company', 'ssn', 'passportNumber',
    'licenseNumber', 'email', 'phone', 'address1', 'address2', 'address3', 'city', 'state', 'postalCode', 'country'] },
  5: { name: 'sshKey', keys: ['privateKey', 'publicKey', 'keyFingerprint'] },
  6: { name: 'bankAccount', keys: ['bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber',
    'branchNumber', 'pin', 'swiftCode', 'iban', 'bankContactPhone'] },
  7: { name: 'driversLicense', keys: ['firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber',
    'issuingCountry', 'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass'] },
  8: { name: 'passport', keys: ['surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry',
    'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority', 'issueDate', 'expirationDate'] },
};
export const fieldLabel: Record<string, string> = {
  totp: 'Authenticator key', cardholderName: 'Cardholder name', expMonth: 'Expiry month', expYear: 'Expiry year', code: 'Security code',
  firstName: 'First name', middleName: 'Middle name', lastName: 'Last name', ssn: 'Social security number',
  passportNumber: 'Passport number', licenseNumber: 'License number', postalCode: 'Postal code',
  privateKey: 'Private key', publicKey: 'Public key', keyFingerprint: 'Fingerprint', fullName: 'Full name',
  bankName: 'Bank name', nameOnAccount: 'Name on account', accountType: 'Account type', accountNumber: 'Account number',
  routingNumber: 'Routing number', branchNumber: 'Branch number', pin: 'PIN', swiftCode: 'SWIFT code', iban: 'IBAN',
  bankContactPhone: 'Bank contact phone', dateOfBirth: 'Date of birth', issuingCountry: 'Issuing country',
  issuingState: 'Issuing state', issueDate: 'Issue date', expirationDate: 'Expiration date',
  issuingAuthority: 'Issuing authority', licenseClass: 'License class', givenName: 'Given name',
  birthPlace: 'Place of birth', passportType: 'Passport type', nationalIdentificationNumber: 'National identification number',
};
export const secretFields = new Set(['password', 'totp', 'number', 'code', 'ssn', 'passportNumber', 'licenseNumber', 'privateKey',
  'accountNumber', 'routingNumber', 'branchNumber', 'pin', 'iban', 'nationalIdentificationNumber']);
type Website = Record<string, unknown> & { uri: string; match?: number | null };
export type ItemDraft = {
  name: string; folder: string; favorite: boolean; notes: string;
  values: Record<string, string>; urls: Website[]; fields: CustomField[];
};
const object = (value: unknown) => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const websites = (value: unknown) => Array.isArray(value) ? value.filter((entry): entry is Website => typeof object(entry).uri === 'string') : [];
const string = (value: unknown) => typeof value === 'string' ? value : '';
export const itemType = (item?: ImportedItem) => typeof item?.source.type === 'number' ? item.source.type : 2;
export const itemKeys = (type: number) => sections[type]?.keys ?? [];

export function itemDraft(item?: ImportedItem, note = ''): ItemDraft {
  const source = item?.source ?? {}, section = sections[itemType(item)];
  const details = section ? object(source[section.name]) : {};
  return {
    name: item?.name ?? '', folder: item?.folder ?? '', favorite: source.favorite === true, notes: item ? string(source.notes) : note,
    values: Object.fromEntries((section?.keys ?? []).map(key => [key, string(details[key])])),
    urls: itemType(item) === 1 ? websites(details.uris) : [], fields: fieldsFrom(source.fields),
  };
}

export function makeItem(type: ItemType): ImportedItem {
  const kind = ITEM_TYPES[type], section = sections[type];
  return { name: `Untitled ${kind.toLowerCase()}`, folder: '', kind, source: { type, notes: '', ...(section ? { [section.name]: {} } : {}) } };
}

function checked(value: unknown, max: number) {
  if (typeof value !== 'string' || value.length > max) throw Error('An item field exceeds its supported length');
  return value;
}
export function reviseItem(item: ImportedItem | undefined, draft: ItemDraft, note: string): ImportedItem | undefined {
  const type = itemType(item), section = sections[type], previous = item?.source ?? {};
  const name = checked(draft.name, 256).trim(), folder = checked(draft.folder, 256).trim();
  const fields = validateFieldEdits(draft.fields, previous.fields, type);
  if (!item && !name && !folder && !draft.favorite && !fields.length) return;
  const result = item ?? makeItem(2);
  const source: Record<string, unknown> = { ...result.source, name: name || result.name, favorite: draft.favorite === true,
    notes: type === 2 ? note : checked(draft.notes, 1_000_000), fields };
  if (section) {
    const original = object(previous[section.name]), details = { ...original };
    for (const key of section.keys) {
      const edited = checked(draft.values[key], 65_536);
      if (edited !== string(original[key])) details[key] = edited;
    }
    if (type === 1) {
      const previousPassword = string(original.password);
      if (previousPassword && details.password !== previousPassword) {
        source.passwordHistory = [{ password: previousPassword, lastUsedDate: new Date().toISOString() },
          ...(Array.isArray(previous.passwordHistory) ? previous.passwordHistory : [])];
      }
      if (!Array.isArray(draft.urls) || draft.urls.length > 128) throw Error('Use up to 128 website URLs');
      const input = websites(draft.urls);
      if (input.length !== draft.urls.length) throw Error('Invalid website URL');
      const prior = Array.isArray(original.uris) ? original.uris : [];
      const unsupported = prior.filter(value => websites([value]).length === 0);
      details.uris = [...input.filter(entry => entry.uri.trim()).map(entry => {
        const uri = checked(entry.uri, 4096);
        if (entry.match != null && (!Number.isInteger(entry.match) || entry.match < 0 || entry.match > 5)) {
          if (!prior.some(value => JSON.stringify(value) === JSON.stringify(entry))) throw Error('Invalid website matching rule');
        }
        return { ...entry, uri };
      }), ...unsupported];
    }
    source[section.name] = details;
  }
  return { ...result, name: name || result.name, folder, source };
}
