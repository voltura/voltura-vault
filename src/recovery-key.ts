import { sodium, wipe } from './crypto.ts';

const header = 'voltura-vault-recovery-v1\n';
const encoding = () => sodium.base64_variants.URLSAFE_NO_PADDING;

export function parseKey(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw Error('Invalid vault key file.');
  const key = sodium.from_base64(value, encoding());
  if (key.length === 32 && sodium.to_base64(key, encoding()) === value) return key;
  wipe(key);
  throw Error('Invalid vault key file.');
}

export function parseRecoveryText(text: string) {
  if (!text.startsWith(header)) throw Error('Invalid Voltura Vault recovery key file.');
  return parseKey(text.slice(header.length).replace(/\r?\n$/, ''));
}

export function recoveryText(key: Uint8Array) {
  return header + sodium.to_base64(key, encoding()) + '\n';
}
