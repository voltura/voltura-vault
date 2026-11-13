import { readPreference } from './preferences';

export const CLIPBOARD_TIMEOUTS = [15, 30, 60, 120];
export const windowsClipboard = () =>
  location.origin === 'https://tauri.localhost' && '__TAURI_INTERNALS__' in window;

export function readClipboardTimeout() {
  const seconds = Number(readPreference('vault-clipboard-seconds', '30'));
  return CLIPBOARD_TIMEOUTS.includes(seconds) ? seconds : 30;
}

export async function copyToClipboard(value: string, seconds: number) {
  if (windowsClipboard()) {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('copy_to_windows_clipboard', { value, seconds });
    return;
  }
  await navigator.clipboard.writeText(value);
}
