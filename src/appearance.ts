export const PALETTES = [
  { value: 'vault', label: 'Vault Blue' },
  { value: 'forest', label: 'Forest' },
  { value: 'retro-wood', label: 'Retro Wood' },
  { value: 'modern-metallic', label: 'Modern Metallic' },
  { value: 'modern-black', label: 'Modern Black' },
  { value: 'midnight', label: 'Midnight' },
  { value: 'matrix', label: 'Matrix' },
  { value: 'blood-red', label: 'Blood Red' },
  { value: 'burnt-orange', label: 'Burnt Orange' },
  { value: 'golden-god', label: 'Golden God' },
  { value: 'pink-panther', label: 'Pink Panther' },
];

export function validPalette(value: string) {
  return PALETTES.some(option => option.value === value) ? value : 'vault';
}
