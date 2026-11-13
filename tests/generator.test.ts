import { describe, expect, it } from 'vitest';
import { generatePassword, generatePassphrase, PASSWORD_DEFAULTS } from '../src/generator';
import englishSource from '../src/dictionaries/eff.txt?raw';

describe('credential generation', () => {
  it('meets exact quotas even when no other character can fit', () => {
    const { value } = generatePassword({ ...PASSWORD_DEFAULTS, length: 128, minimumDigits: 64, minimumSymbols: 64 });
    expect(value).toHaveLength(128);
    expect(value.match(/[2-9]/g)).toHaveLength(64);
    expect(value.match(/[!@#$%^&*]/g)).toHaveLength(64);
    expect(value).not.toMatch(/[0O1lI]/);
  });

  it('rejects impossible constraints', () => {
    expect(() => generatePassword({ ...PASSWORD_DEFAULTS, length: 5, minimumDigits: 4, minimumSymbols: 2 })).toThrow();
    expect(() => generatePassword({ ...PASSWORD_DEFAULTS, upper: false, lower: false, digits: false, symbols: false })).toThrow();
  });

  it('draws mixed-language passphrases from the supplied words', () => {
    const english = new Set(englishSource.trim().split(/\r?\n/).map(line => line.trim().split(/\s+/)[1]));
    const { value } = generatePassphrase({ count: 6, separator: '|', capitalize: false, includeNumber: false });
    const words = value.split('|');
    expect(words).toHaveLength(6);
    expect(words.some(word => english.has(word))).toBe(true);
    expect(words.some(word => !english.has(word))).toBe(true);
  });
});
