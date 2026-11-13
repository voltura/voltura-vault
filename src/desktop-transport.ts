export type Discovery = { protocolVersion: 1; setupRequired: boolean; vaultId?: string };
export type VaultCall = {
  path: string; method: string; body?: string; token?: string; writeKey?: string; proof?: string;
};
export type VaultOperation = { kind: 'request'; call: VaultCall } | { kind: 'commit'; vaultId: string }
  | { kind: 'profile' };
type Message = VaultOperation & { id: number };

export async function connectDesktop(url: string, file?: File) {
  if (file && (file.size === 0 || file.size > 32 * 1024)) throw Error('Select a public CA certificate smaller than 32 KB.');
  const ca = file ? btoa(String.fromCharCode(...new Uint8Array(await file.arrayBuffer()))) : undefined;
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<Discovery>('vault_connect', { url: url.trim(), ca });
}

export async function desktopOperation(message: Message): Promise<ArrayBuffer | string | null> {
  const { invoke } = await import('@tauri-apps/api/core');
  switch (message.kind) {
    case 'request': return invoke<ArrayBuffer>('vault_request', { call: message.call });
    case 'commit': return invoke<string>('vault_commit', { vaultId: message.vaultId });
    case 'profile': return invoke<string | null>('vault_profile');
  }
}
