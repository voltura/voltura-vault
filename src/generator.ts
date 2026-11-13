import englishSource from './dictionaries/eff.txt?raw';
import swedishSource from './dictionaries/sv-diceware-7776.plain.txt?raw';

export const CHARACTER_SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789', symbols: '!@#$%^&*',
};
export type PasswordOptions = Record<keyof typeof CHARACTER_SETS, boolean> & {
  length: number; minimumDigits: number; minimumSymbols: number; avoidAmbiguous: boolean;
};
export const PASSWORD_DEFAULTS: PasswordOptions = {
  length: 30, upper: true, lower: true, digits: true, symbols: true,
  minimumDigits: 1, minimumSymbols: 2, avoidAmbiguous: true,
};
type WordOptions = { capitalize: boolean; includeNumber: boolean };
type PhraseOptions = WordOptions & { count: number; separator: string };
export type GeneratedSecret = { value: string; bits?: number };

function randomBelow(limit: bigint) {
  if (limit <= 1n) return 0n;
  const bits = (limit - 1n).toString(2).length;
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  const mask = (1 << (8 - (bytes.length * 8 - bits))) - 1;
  for (;;) {
    crypto.getRandomValues(bytes);
    bytes[0] &= mask;
    let result = 0n;
    for (const byte of bytes) result = (result << 8n) + BigInt(byte);
    if (result < limit) return result;
  }
}
const pick = (length: number) => Number(randomBelow(BigInt(length)));

export function generatePassword(options: PasswordOptions): GeneratedSecret {
  const { length } = options;
  if (!Number.isInteger(length) || length < 5 || length > 128) throw Error('Enter a length from 5 to 128.');
  const letters = (options.upper ? CHARACTER_SETS.upper : '') + (options.lower ? CHARACTER_SETS.lower : '');
  const groups = [letters, options.digits ? CHARACTER_SETS.digits : '', options.symbols ? CHARACTER_SETS.symbols : '']
    .map(group => options.avoidAmbiguous ? group.replace(/[0O1lI]/g, '') : group);
  let digits = options.digits ? options.minimumDigits : 0, symbols = options.symbols ? options.minimumSymbols : 0;
  if (!Number.isInteger(digits) || !Number.isInteger(symbols) || digits < 0 || symbols < 0 || digits + symbols > length) {
    throw Error('The minimum numbers and symbols must fit within the password length.');
  }
  if (!groups.some(Boolean)) throw Error('Select at least one character group.');
  // Count valid completions so each password satisfying the settings is equally likely.
  const sizes = groups.map(group => BigInt(group.length));
  const table = new Map<number, bigint>();
  function count(left: number, numbers: number, special: number): bigint {
    if (left < numbers + special) return 0n;
    if (!numbers && !special) return BigInt(groups.join('').length) ** BigInt(left);
    const key = (left * 129 + numbers) * 129 + special;
    const cached = table.get(key);
    if (cached !== undefined) return cached;
    const total = sizes[0] * count(left - 1, numbers, special)
      + sizes[1] * count(left - 1, Math.max(0, numbers - 1), special)
      + sizes[2] * count(left - 1, numbers, Math.max(0, special - 1));
    table.set(key, total);
    return total;
  }
  const total = count(length, digits, symbols);
  let value = '';
  for (let left = length; left > 0; left--) {
    let draw = randomBelow(count(left, digits, symbols));
    for (let group = 0; group < groups.length; group++) {
      if (!sizes[group]) continue;
      const nextDigits = Math.max(0, digits - Number(group === 1));
      const nextSymbols = Math.max(0, symbols - Number(group === 2));
      const weight = sizes[group] * count(left - 1, nextDigits, nextSymbols);
      if (draw < weight) {
        value += groups[group][pick(groups[group].length)];
        digits = nextDigits; symbols = nextSymbols;
        break;
      }
      draw -= weight;
    }
  }
  return { value, bits: Math.floor(Math.log2(Number(total))) };
}

const english = [...new Set(englishSource.trim().split(/\r?\n/).map(line => line.trim().split(/\s+/)[1]).filter(Boolean))];
// The upstream Swedish list is transliterated. Include ordinary Swedish spellings with diacritics as additional choices.
const accents = 'åker åska ål ånga årsdag åra ås årstid årtal åkerbär ära älg äpple äng äventyr älv älskling ättika ägg ämne öga öra öken öde ödla öring örn örter ögonblick önskan höst blåbär råg väska bröd päron grön björk bänk färg gård källa körsbär löv mjöl måne näbb nöt räka rådjur räv sjö skär snö säd tång träd vagnståg vägg väv vår våg värme'.split(' ');
const englishSet = new Set(english);
const swedish = new Set([...swedishSource.trim().split(/\s+/), ...accents].map(word => word.normalize('NFC')));
const mixed = [...new Set([...english, ...swedish])];
const englishOnly = new Set(english.filter(word => !swedish.has(word)));
const swedishOnly = new Set([...swedish].filter(word => !englishSet.has(word)));

const capitalize = (word: string) => word[0].toUpperCase() + word.slice(1);
const digit = () => String(pick(10));
export function generateUsername(options: WordOptions): GeneratedSecret {
  const word = english[pick(english.length)];
  return { value: (options.capitalize ? capitalize(word) : word) + (options.includeNumber ? digit() : '') };
}

export function generatePassphrase(options: PhraseOptions): GeneratedSecret {
  const { count, separator } = options;
  if (!Number.isInteger(count) || count < 3 || count > 20) throw Error('Enter a word count from 3 to 20.');
  let words: string[];
  do { words = Array.from({ length: count }, () => mixed[pick(mixed.length)]); }
  while (!words.some(word => englishOnly.has(word)) || !words.some(word => swedishOnly.has(word)));
  if (options.capitalize) words = words.map(capitalize);
  if (options.includeNumber) words[pick(words.length)] += digit();
  return { value: words.join(separator) };
}
