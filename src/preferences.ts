export const TIMEOUTS = [5, 10, 15, 30, 60] as const;
export function readPreference(key: string, fallback: string) {
  try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
}
export function writePreference(key: string, value: string) {
  try { localStorage.setItem(key, value); } catch { /* In-memory preferences still work when storage is denied. */ }
}
export function readTimeout() {
  const value = Number(readPreference('vault-idle-minutes', '5'));
  return TIMEOUTS.some(n => n === value) ? value : 5;
}
