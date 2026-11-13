import type { HelloCredential } from './format';

const localDeviceHint = { hints: ['client-device'] };
const RP = 'vault-ui.test';

// A short label lets the owner distinguish browser enrollments in the Windows picker.
export function browserHelloLabel(input: Uint8Array) {
  const suffix = Array.from(input.subarray(0, 4), byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return 'Voltura Vault ' + suffix;
}
const PROVIDERS = new Set([
  '08987058cadc4b81b6e130de50dcbe96',
  '9ddd1817af5a4672a2b93e3dd95000a9',
  '6028b017b1d44c02b4b3afcdafc96bb2',
]);
const native = () => location.origin === 'https://tauri.localhost' && '__TAURI_INTERNALS__' in window;
export const canUseHello = () => native() || (
  location.origin === `https://${RP}` && /^Win/.test(navigator.platform) && typeof PublicKeyCredential !== 'undefined'
);

async function checkAuthenticatorData(data: Uint8Array, enrollment = false) {
  const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(RP)));
  if (data.length < 37 || !rpHash.every((byte, index) => byte === data[index])
      || (data[32] & 5) !== 5 || (data[32] & 0x18) !== 0) {
    throw Error('Choose Windows Hello on this PC.');
  }
  if (enrollment) {
    const provider = Array.from(data.subarray(37, 53), byte => byte.toString(16).padStart(2, '0')).join('');
    if (data.length < 55 || !(data[32] & 0x40) || !PROVIDERS.has(provider)) {
      throw Error('Choose Windows Hello on this PC when saving the passkey.');
    }
  }
}

function prfResult(credential: PublicKeyCredential) {
  const result = credential.getClientExtensionResults().prf?.results?.first;
  if (!result || result.byteLength !== 32) return undefined;
  return ArrayBuffer.isView(result)
    ? new Uint8Array(result.buffer, result.byteOffset, result.byteLength) : new Uint8Array(result);
}

export async function enrollHello(): Promise<{ credential: HelloCredential; secret?: Uint8Array }> {
  const input = crypto.getRandomValues(new Uint8Array(32));
  if (native()) {
    const { invoke } = await import('@tauri-apps/api/core');
    return { credential: { id: await invoke<string>('hello_enroll', { input: Array.from(input) }), input } };
  }
  if (!canUseHello()) throw Error('Open the installed Windows app to set up Windows Hello.');
  const credential = await navigator.credentials.create({ publicKey: {
    rp: { id: RP, name: 'Voltura Vault' },
    user: { id: crypto.getRandomValues(new Uint8Array(32)), name: browserHelloLabel(input), displayName: browserHelloLabel(input) },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
    ...localDeviceHint, attestation: 'direct', timeout: 60_000,
    extensions: { prf: { eval: { first: input } } },
  } }) as PublicKeyCredential | null;
  if (!credential) throw Error('Windows Hello setup was cancelled.');
  await checkAuthenticatorData(new Uint8Array((credential.response as AuthenticatorAttestationResponse).getAuthenticatorData()), true);
  if (credential.authenticatorAttachment === 'cross-platform') {
    throw Error('Choose Windows Hello on this PC when saving the passkey.');
  }
  // Some providers only return the PRF result on a subsequent assertion.
  return { credential: { id: credential.id, input }, secret: prfResult(credential) };
}

export async function evaluateHello({ id, input }: HelloCredential): Promise<Uint8Array> {
  if (native()) {
    const { invoke } = await import('@tauri-apps/api/core');
    return new Uint8Array(await invoke<ArrayBuffer>('hello_evaluate', { credentialId: id, input: Array.from(input) }));
  }
  if (!canUseHello()) throw Error('Open the installed Windows app to use Windows Hello.');
  const credentialId = Uint8Array.from(atob(id.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
  const assertion = await navigator.credentials.get({ mediation: 'required', publicKey: {
    rpId: RP, challenge: crypto.getRandomValues(new Uint8Array(32)), timeout: 60_000,
    ...localDeviceHint,
    allowCredentials: [{ type: 'public-key', id: credentialId }],
    userVerification: 'required', extensions: { prf: { eval: { first: Uint8Array.from(input) } } },
  } }) as PublicKeyCredential | null;
  if (!assertion || assertion.id !== id) throw Error('Windows Hello did not return the passkey registered for this vault.');
  if (assertion.authenticatorAttachment === 'cross-platform') throw Error('Choose Windows Hello on this PC.');
  const bytes = prfResult(assertion);
  if (!bytes) throw Error('This Windows Hello passkey cannot unlock the vault.');
  try {
    await checkAuthenticatorData(new Uint8Array((assertion.response as AuthenticatorAssertionResponse).authenticatorData));
    return bytes;
  } catch (error) { bytes.fill(0); throw error; }
}
