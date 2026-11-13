import type { VaultOperation } from './desktop-transport';

export const publicDesktop = import.meta.env.VITE_VAULT_PUBLIC_DESKTOP === true;
let channel: MessagePort | undefined;
let next = 0;
const waiting = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();

export function setDesktopChannel(port: MessagePort) {
  if (!publicDesktop || channel) return;
  channel = port;
  channel.onmessage = ({ data }) => {
    const pending = waiting.get(data.id);
    if (!pending) return;
    waiting.delete(data.id);
    if (typeof data.error === 'string') pending.reject(Error(data.error));
    else pending.resolve(data.value);
  };
}

export async function callDesktop<T>(message: VaultOperation): Promise<T> {
  if (!channel) throw Error('Open the installed Voltura Vault desktop app.');
  const id = ++next;
  return new Promise<T>((resolve, reject) => {
    waiting.set(id, { resolve: value => resolve(value as T), reject });
    try { channel!.postMessage({ ...message, id }); }
    catch { waiting.delete(id); reject(Error('Could not send the Vault request.')); }
  });
}
