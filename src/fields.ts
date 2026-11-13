export type CustomField = Record<string, unknown> & { name: string; value?: string | null; type: number; linkedId?: number; volturaType?: string };
export type EditableFieldType = 'text' | 'number' | 'hidden' | 'boolean' | 'linked';
export const linkedOptions: Partial<Record<number, Record<number, string>>> = {
  1: { 100: 'username', 101: 'password' },
  3: { 300: 'cardholderName', 301: 'expMonth', 302: 'expYear', 303: 'code', 304: 'brand', 305: 'number' },
  4: { 400: 'title', 401: 'middleName', 402: 'address1', 403: 'address2', 404: 'address3', 405: 'city', 406: 'state',
    407: 'postalCode', 408: 'country', 409: 'company', 410: 'email', 411: 'phone', 412: 'ssn', 413: 'username',
    414: 'passportNumber', 415: 'licenseNumber', 416: 'firstName', 417: 'lastName', 418: 'fullName' },
};

export function fieldsFrom(value: unknown): CustomField[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is CustomField => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
    return typeof entry.name === 'string' && (entry.value == null || typeof entry.value === 'string') && typeof entry.type === 'number';
  });
}

export function fieldType(field: CustomField): EditableFieldType | 'preserved' {
  if (field.type === 0) return field.volturaType === 'number' ? 'number' : 'text';
  if (field.type === 1) return 'hidden';
  if (field.type === 2) return 'boolean';
  const id = field.linkedId;
  if (field.type === 3 && typeof id === 'number' && Number.isSafeInteger(id)
    && Object.values(linkedOptions).some(options => Object.hasOwn(options!, id))) return 'linked';
  return 'preserved';
}

export function changeFieldType(field: CustomField, type: EditableFieldType, defaultLink = 100): CustomField {
  const { volturaType: _, linkedId: __, ...rest } = field;
  return {
    ...rest,
    type: type === 'hidden' ? 1 : type === 'boolean' ? 2 : type === 'linked' ? 3 : 0,
    ...(type === 'number' ? { volturaType: 'number' } : {}),
    ...(type === 'linked' ? { linkedId: defaultLink } : {}),
    value: type === 'linked' ? null : type === 'boolean' ? String(field.value?.toLowerCase() === 'true') : field.value ?? '',
  };
}

export function validateFieldEdits(value: unknown, original: unknown, itemType: number): unknown[] {
  const fields = fieldsFrom(value);
  if (!Array.isArray(value) || value.length > 128 || fields.length !== value.length) throw Error('Use up to 128 custom fields');
  const previous = Array.isArray(original) ? original : [];
  const originalPreserved = previous.filter(entry => fieldsFrom([entry]).length === 0 || fieldType(entry as CustomField) === 'preserved');
  const submittedPreserved = fields.filter(field => fieldType(field) === 'preserved');
  const existingLinked = originalPreserved.filter(entry => fieldsFrom([entry]).length === 1);
  if (JSON.stringify(submittedPreserved) !== JSON.stringify(existingLinked)) throw Error('This imported custom field type is preserved');
  for (const field of fields) {
    const type = fieldType(field);
    if (type === 'preserved') continue;
    if (previous.some(entry => JSON.stringify(entry) === JSON.stringify(field))) continue;
    const text = field.value ?? '';
    if (!field.name.trim() || field.name.length > 256 || text.length > 65_536) throw Error('Each custom field needs a name and a value within the supported length');
    if (type === 'number' && text !== '' && !/^-?\d+(?:\.\d+)?$/.test(text)) throw Error(`Enter a number for ${field.name}`);
    if (type === 'boolean' && !['true', 'false'].includes(text.toLowerCase())) throw Error('A checkbox must be on or off');
    if (type === 'linked' && !linkedOptions[itemType]?.[field.linkedId!]) throw Error('Choose a linked value from this item');
  }
  return [...fields, ...originalPreserved.filter(entry => !fieldsFrom([entry]).length)];
}
